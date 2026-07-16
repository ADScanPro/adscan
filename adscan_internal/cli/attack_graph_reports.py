"""CLI helpers for BloodHound-related commands.

This module handles ACE enumeration and other BloodHound operations.
"""

from __future__ import annotations

from typing import Any, Protocol
from collections import defaultdict
import os
import sys
import re
from datetime import datetime, timezone

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.box import ROUNDED, SIMPLE
from rich.console import Group
from rich.text import Text
from rich.panel import Panel

from adscan_core.theme import (
    ADSCAN_PRIMARY,
    COLOR_AMBER,
    COLOR_CRIMSON,
    COLOR_MUTED,
    COLOR_SAGE,
    COLOR_STEEL,
)

from adscan_internal import (
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_info_table,
    print_info_list,
    print_info_verbose,
    print_operation_header,
    print_success,
    print_success_verbose,
    print_warning,
    telemetry,
)
from adscan_internal.cli.ci_events import emit_event
from adscan_internal.cli.compromise_render import (
    render_kpi_panel,
    render_tiering_legend,
)
from adscan_internal.reporting_compat import handle_optional_report_service_exception
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_core.output._state import _get_console
from adscan_internal.services.high_value import (
    UserRiskFlags,
    classify_users_tier0_high_value,
    normalize_samaccountname,
)
from adscan_internal.services.identity_risk_service import (
    build_identity_risk_snapshot,
    CONTROL_EXPOSURE_IDENTITIES_FILENAME,
    DIRECT_DOMAIN_CONTROL_IDENTITIES_FILENAME,
    DOMAIN_COMPROMISE_ENABLERS_FILENAME,
    HIGH_IMPACT_PRIVILEGES_FILENAME,
    get_identity_risk_record,
    load_or_build_identity_risk_snapshot,
)
from adscan_internal.services.identity_choke_point_service import (
    build_identity_choke_point_snapshot,
)
from adscan_internal.services.adcs_path_display import (
    resolve_adcs_display_target,
)
from adscan_internal.services.adcs_target_filter import (
    domain_has_adcs_for_attack_steps,
    path_contains_adcs_dependent_node,
)
from adscan_internal.services.attack_graph_service import (
    ATTACK_PATHS_MAX_DEPTH_USER,
    load_attack_graph,
)
from adscan_internal.services.attack_step_support_registry import (
    describe_search_mode_label,
)
from adscan_internal.workspaces import domain_relpath, domain_subpath, write_json_file


# Compute-time path cap for `attack_paths` UX.
# Set to `None` (default) for unlimited path computation, or to a positive int.
ATTACK_PATHS_COMPUTE_DEFAULT_MAX: int | None = None


def _get_attack_paths_step_sample_limit() -> int:
    """Return maximum number of attack-step samples to print per discovery step."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_STEP_SAMPLE_LIMIT", "20")
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 20
    return max(0, min(limit, 200))


def _get_attack_paths_step_show_samples() -> bool:
    """Return whether to show sampled steps (capped) to the user."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_STEP_SHOW_SAMPLES", "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _get_acl_sanitization_threshold() -> int:
    """Return the ACL per-source threshold above which sanitization is applied."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_ACL_SANITIZE_THRESHOLD", "100")
    try:
        threshold = int(raw)
    except (TypeError, ValueError):
        threshold = 100
    return max(0, threshold)


def _get_acl_sanitization_depth() -> int:
    """Return the bounded DFS depth used for noisy ACL source sanitization."""
    raw = os.getenv("ADSCAN_ATTACK_PATHS_ACL_SANITIZE_DEPTH", "5")
    try:
        depth = int(raw)
    except (TypeError, ValueError):
        depth = 5
    return max(1, min(depth, 12))


def _bloodhound_node_display_label(node: object) -> str:
    """Return a stable human-readable label for a BloodHound node payload."""
    if not isinstance(node, dict):
        return str(node or "").strip()
    props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    name = (
        props.get("name")
        or props.get("samaccountname")
        or props.get("samAccountName")
        or node.get("name")
        or node.get("samaccountname")
        or node.get("samAccountName")
        or node.get("label")
        or node.get("objectId")
        or ""
    )
    return str(name or "").strip()


def _bloodhound_node_primary_kind(node: object) -> str:
    """Return the primary BloodHound kind for one node payload."""
    if not isinstance(node, dict):
        return ""
    kind = node.get("kind") or node.get("labels") or node.get("type")
    if isinstance(kind, list) and kind:
        preferred = {
            "User",
            "Computer",
            "Group",
            "Domain",
            "GPO",
            "OU",
            "Container",
            "CertTemplate",
            "EnterpriseCA",
            "AIACA",
            "RootCA",
            "NTAuthStore",
        }
        for entry in kind:
            entry_text = str(entry or "").strip()
            if entry_text in preferred:
                return entry_text
        return str(kind[0] or "").strip()
    if isinstance(kind, str):
        return kind.strip()
    properties = node.get("properties")
    if isinstance(properties, dict):
        fallback = properties.get("type") or properties.get("objecttype")
        if isinstance(fallback, str):
            return fallback.strip()
    return ""


def _write_acl_object_control_coverage_sidecar(
    shell: BloodHoundShell,
    *,
    domain: str,
    valid_entries: list[dict[str, Any]],
    direct_entries: list[dict[str, Any]],
    promoted_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Persist compact object-control coverage derived from raw ACL inventory."""
    from adscan_internal.services.attack_graph_service import _node_id
    from adscan_internal.workspaces import write_json_file

    direct_signatures: set[tuple[str, str, str]] = set()
    promoted_signatures: set[tuple[str, str, str]] = set()
    for entry in direct_entries:
        nodes = entry.get("nodes") or []
        rels = entry.get("rels") or []
        if len(nodes) < 2 or not rels:
            continue
        if not isinstance(nodes[0], dict) or not isinstance(nodes[1], dict):
            continue
        direct_signatures.add(
            (
                _node_id(nodes[0]),
                _node_id(nodes[1]),
                str(rels[0] or "").strip().lower(),
            )
        )
    for entry in promoted_entries:
        nodes = entry.get("nodes") or []
        rels = entry.get("rels") or []
        if len(nodes) < 2 or not rels:
            continue
        if not isinstance(nodes[0], dict) or not isinstance(nodes[1], dict):
            continue
        promoted_signatures.add(
            (
                _node_id(nodes[0]),
                _node_id(nodes[1]),
                str(rels[0] or "").strip().lower(),
            )
        )

    coverage_records: list[dict[str, Any]] = []
    seen_records: set[tuple[str, str, str]] = set()
    summary = {
        "records_total": 0,
        "retained_direct": 0,
        "retained_promoted": 0,
        "dropped": 0,
    }

    for entry in valid_entries:
        nodes = entry.get("nodes") or []
        rels = entry.get("rels") or []
        if len(nodes) < 2 or not rels:
            continue
        if not isinstance(nodes[0], dict) or not isinstance(nodes[1], dict):
            continue
        relation = str(rels[0] or "").strip()
        relation_norm = relation.lower()
        if relation_norm not in {"genericall", "genericwrite"}:
            continue
        target_kind = _bloodhound_node_primary_kind(nodes[1])
        if target_kind.lower() != "user":
            continue
        source_id = _node_id(nodes[0])
        target_id = _node_id(nodes[1])
        if not source_id or not target_id:
            continue
        signature = (source_id, target_id, relation_norm)
        if signature in seen_records:
            continue
        seen_records.add(signature)
        if signature in direct_signatures:
            disposition = "retained_direct"
        elif signature in promoted_signatures:
            disposition = "retained_promoted"
        else:
            disposition = "dropped"
        summary["records_total"] += 1
        summary[disposition] += 1
        coverage_records.append(
            {
                "source_id": source_id,
                "source_graph_id": source_id,
                "source_object_id": str(
                    nodes[0].get("objectId")
                    or (
                        nodes[0].get("properties")
                        if isinstance(nodes[0].get("properties"), dict)
                        else {}
                    ).get("objectid")
                    or ""
                ).strip(),
                "source": _bloodhound_node_display_label(nodes[0]),
                "target_id": target_id,
                "target_graph_id": target_id,
                "target_object_id": str(
                    nodes[1].get("objectId")
                    or (
                        nodes[1].get("properties")
                        if isinstance(nodes[1].get("properties"), dict)
                        else {}
                    ).get("objectid")
                    or ""
                ).strip(),
                "target": _bloodhound_node_display_label(nodes[1]),
                "relation": relation,
                "target_kind": target_kind,
                "disposition": disposition,
            }
        )

    payload = {
        "schema_version": "acl-object-control-coverage-1.1",
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "coverage": coverage_records,
        "summary": summary,
    }
    output_path = domain_subpath(
        shell._get_workspace_cwd(),
        shell.domains_dir,
        domain,
        "BH",
        "acl_object_control_coverage.json",
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    write_json_file(output_path, payload)
    print_info_debug(
        "[bloodhound] ACL object-control coverage: "
        f"total={summary['records_total']} "
        f"retained_direct={summary['retained_direct']} "
        f"retained_promoted={summary['retained_promoted']} "
        f"dropped={summary['dropped']} "
        f"path={mark_sensitive(output_path, 'path')}"
    )
    return payload


def _sanitize_acl_paths_for_attack_graph(
    shell: BloodHoundShell,
    *,
    domain: str,
    graph: dict[str, Any],
    raw_paths: list[dict[str, Any]],
    max_depth: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return ACL edges to persist after per-source noise sanitization.

    Strategy:
    - Sources with fewer than ``X`` ACL edges are persisted directly.
    - Sources with ``>= X`` ACL edges are only persisted when one of their ACL
      edges participates in a bounded high-value path on an in-memory runtime
      graph that includes all ACL candidates plus the already-built graph.
    """
    from adscan_internal.services import attack_graph_core
    from adscan_internal.services.attack_graph_service import (  # local import avoids cycle
        _node_id,
        add_bloodhound_path_edges,
    )

    threshold = _get_acl_sanitization_threshold()
    sanitize_depth = max(max_depth, _get_acl_sanitization_depth())

    valid_entries: list[dict[str, Any]] = []
    source_to_entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
    source_to_label: dict[str, str] = {}
    has_adcs: bool | None = None
    adcs_filtered_rows = 0
    adcs_filtered_samples: list[dict[str, str]] = []

    for entry in raw_paths:
        if not isinstance(entry, dict):
            continue
        nodes = entry.get("nodes") or []
        rels = entry.get("rels") or []
        if not isinstance(nodes, list) or not isinstance(rels, list):
            continue
        if len(nodes) < 2 or not rels:
            continue
        if not isinstance(nodes[0], dict) or not isinstance(nodes[1], dict):
            continue
        target_label = _bloodhound_node_display_label(nodes[1])
        if path_contains_adcs_dependent_node(nodes, domain, skip_first=True):
            if has_adcs is None:
                has_adcs = domain_has_adcs_for_attack_steps(shell, domain)
            if not has_adcs:
                adcs_filtered_rows += 1
                if len(adcs_filtered_samples) < 20:
                    adcs_filtered_samples.append(
                        {
                            "source": _bloodhound_node_display_label(nodes[0]),
                            "relation": str(rels[0] or ""),
                            "target": target_label,
                        }
                    )
                continue
        source_id = _node_id(nodes[0])
        if not source_id:
            continue
        source_to_entries[source_id].append(entry)
        source_to_label.setdefault(source_id, _bloodhound_node_display_label(nodes[0]))
        valid_entries.append(entry)

    report: dict[str, Any] = {
        "domain": domain,
        "threshold": threshold,
        "sanitization_depth": sanitize_depth,
        "total_acl_rows": len(valid_entries),
        "direct_sources": 0,
        "noisy_sources": 0,
        "direct_acl_rows": 0,
        "promoted_acl_rows": 0,
        "dropped_acl_rows": 0,
        "top_noisy_sources": [],
        "direct_samples": [],
        "promoted_samples": [],
        "retained_sources": [],
        "dropped_sources": [],
        "final_retained_sources_count": 0,
        "fully_dropped_sources_count": 0,
        "adcs_filtered_rows": adcs_filtered_rows,
        "adcs_filtered_samples": adcs_filtered_samples,
    }

    if threshold <= 0 or not valid_entries:
        report["direct_sources"] = len(source_to_entries)
        report["direct_acl_rows"] = len(valid_entries)
        try:
            _write_acl_object_control_coverage_sidecar(
                shell,
                domain=domain,
                valid_entries=valid_entries,
                direct_entries=valid_entries,
                promoted_entries=[],
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[bloodhound] failed to write ACL object-control coverage: {exc}"
            )
        return valid_entries, report

    direct_entries: list[dict[str, Any]] = []
    noisy_entries: dict[str, list[dict[str, Any]]] = {}
    for source_id, entries in source_to_entries.items():
        if len(entries) <= threshold:
            direct_entries.extend(entries)
        else:
            noisy_entries[source_id] = entries

    report["direct_sources"] = len(source_to_entries) - len(noisy_entries)
    report["noisy_sources"] = len(noisy_entries)
    report["direct_acl_rows"] = len(direct_entries)
    report["direct_samples"] = [
        {
            "source": _bloodhound_node_display_label((entry.get("nodes") or [None])[0]),
            "relation": str((entry.get("rels") or [""])[0] or ""),
            "target": _bloodhound_node_display_label(
                (entry.get("nodes") or [None, None])[1]
            ),
        }
        for entry in direct_entries[:20]
        if isinstance(entry, dict)
        and len(entry.get("nodes") or []) >= 2
        and (entry.get("rels") or [])
    ]
    direct_source_counts = {
        source_id: len(entries)
        for source_id, entries in source_to_entries.items()
        if source_id not in noisy_entries
    }

    if not noisy_entries:
        try:
            _write_acl_object_control_coverage_sidecar(
                shell,
                domain=domain,
                valid_entries=valid_entries,
                direct_entries=direct_entries,
                promoted_entries=[],
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[bloodhound] failed to write ACL object-control coverage: {exc}"
            )
        return valid_entries, report

    runtime_graph: dict[str, Any] = dict(graph)
    runtime_graph["nodes"] = dict(
        graph.get("nodes") if isinstance(graph.get("nodes"), dict) else {}
    )
    runtime_graph["edges"] = list(
        graph.get("edges") if isinstance(graph.get("edges"), list) else []
    )

    for entry in valid_entries:
        nodes = [node for node in (entry.get("nodes") or []) if isinstance(node, dict)]
        rels = entry.get("rels") or []
        if len(nodes) < 2 or not isinstance(rels, list):
            continue
        added = add_bloodhound_path_edges(
            runtime_graph,
            nodes=nodes,
            relations=[str(rel) for rel in rels],
            status="discovered",
            edge_type="graph_collection",
            log_creation=False,
            shell=shell,
        )
        _ = added

    noisy_rows: list[dict[str, Any]] = []
    for source_id, entries in noisy_entries.items():
        matched = attack_graph_core.collect_source_step_signatures_on_high_value_paths(
            runtime_graph,
            start_node_id=source_id,
            max_depth=sanitize_depth,
            target_mode="object",
        )

        source_report = {
            "source": source_to_label.get(source_id, source_id),
            "source_id": source_id,
            "acl_count": len(entries),
            "promoted_acl_count": 0,
        }

        for entry in entries:
            nodes = entry.get("nodes") or []
            rels = entry.get("rels") or []
            if len(nodes) < 2 or not rels:
                continue
            if not isinstance(nodes[0], dict) or not isinstance(nodes[1], dict):
                continue
            signature = (
                _node_id(nodes[0]),
                str(rels[0]),
                _node_id(nodes[1]),
            )
            if signature not in matched:
                continue
            noisy_rows.append(entry)
            source_report["promoted_acl_count"] += 1
            if len(report["promoted_samples"]) < 20:
                report["promoted_samples"].append(
                    {
                        "source": _bloodhound_node_display_label(nodes[0]),
                        "relation": str(rels[0] or ""),
                        "target": _bloodhound_node_display_label(nodes[1]),
                    }
                )

        report["top_noisy_sources"].append(source_report)

    kept_paths = direct_entries + noisy_rows
    report["promoted_acl_rows"] = len(noisy_rows)
    report["dropped_acl_rows"] = len(valid_entries) - len(kept_paths)
    report["top_noisy_sources"] = sorted(
        report["top_noisy_sources"],
        key=lambda item: (
            -int(item.get("acl_count", 0)),
            str(item.get("source") or "").lower(),
        ),
    )[:20]
    retained_sources: list[dict[str, Any]] = []
    dropped_sources: list[dict[str, Any]] = []
    for source_id, count in sorted(
        direct_source_counts.items(),
        key=lambda item: (-int(item[1]), source_to_label.get(item[0], item[0]).lower()),
    ):
        retained_sources.append(
            {
                "source": source_to_label.get(source_id, source_id),
                "source_id": source_id,
                "retained_acl_count": count,
                "retention_mode": "direct",
            }
        )
    for item in report["top_noisy_sources"]:
        promoted_count = int(item.get("promoted_acl_count", 0) or 0)
        source_id = str(item.get("source_id") or "")
        source_name = str(item.get("source") or source_id)
        if promoted_count > 0:
            retained_sources.append(
                {
                    "source": source_name,
                    "source_id": source_id,
                    "retained_acl_count": promoted_count,
                    "retention_mode": "sanitized",
                }
            )
        else:
            dropped_sources.append(
                {
                    "source": source_name,
                    "source_id": source_id,
                    "original_acl_count": int(item.get("acl_count", 0) or 0),
                }
            )
    retained_sources = sorted(
        retained_sources,
        key=lambda item: (
            -int(item.get("retained_acl_count", 0)),
            str(item.get("source") or "").lower(),
        ),
    )
    dropped_sources = sorted(
        dropped_sources,
        key=lambda item: (
            -int(item.get("original_acl_count", 0)),
            str(item.get("source") or "").lower(),
        ),
    )
    report["retained_sources"] = retained_sources
    report["dropped_sources"] = dropped_sources
    report["final_retained_sources_count"] = len(retained_sources)
    report["fully_dropped_sources_count"] = len(dropped_sources)

    try:
        output_path = domain_subpath(
            shell._get_workspace_cwd(),
            shell.domains_dir,
            domain,
            "BH",
            "acl_sanitization_report.json",
        )
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        write_json_file(output_path, report)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[bloodhound] failed to write ACL sanitization report: {exc}")

    try:
        _write_acl_object_control_coverage_sidecar(
            shell,
            domain=domain,
            valid_entries=valid_entries,
            direct_entries=direct_entries,
            promoted_entries=noisy_rows,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[bloodhound] failed to write ACL object-control coverage: {exc}"
        )

    print_info_debug(
        "[bloodhound] ACL sanitization: "
        f"total={report['total_acl_rows']} direct={report['direct_acl_rows']} "
        f"promoted={report['promoted_acl_rows']} dropped={report['dropped_acl_rows']} "
        f"adcs_filtered={report['adcs_filtered_rows']} "
        f"threshold={threshold} depth={sanitize_depth}"
    )
    for item in report["adcs_filtered_samples"][:20]:
        print_info_debug(
            "[bloodhound] ACL ADCS-filtered step: "
            f"{mark_sensitive(str(item.get('source') or ''), 'user')} -> "
            f"{str(item.get('relation') or '')} -> "
            f"{mark_sensitive(str(item.get('target') or ''), 'user')}"
        )
    print_info_debug(
        "[bloodhound] ACL sanitization final sources: "
        f"retained={report['final_retained_sources_count']} "
        f"dropped={report['fully_dropped_sources_count']}"
    )
    for item in report["retained_sources"][:20]:
        print_info_debug(
            "[bloodhound] ACL retained source: "
            f"{mark_sensitive(str(item.get('source') or ''), 'user')} "
            f"mode={item.get('retention_mode')} "
            f"retained={item.get('retained_acl_count')}"
        )
    for item in report["top_noisy_sources"]:
        print_info_debug(
            "[bloodhound] ACL noisy source: "
            f"{mark_sensitive(str(item.get('source') or ''), 'user')} "
            f"count={item.get('acl_count')} promoted={item.get('promoted_acl_count')}"
        )
    for item in report["dropped_sources"][:20]:
        print_info_debug(
            "[bloodhound] ACL dropped source: "
            f"{mark_sensitive(str(item.get('source') or ''), 'user')} "
            f"original={item.get('original_acl_count')}"
        )

    return kept_paths, report


def _resolve_attack_paths_compute_cap(max_display: int) -> int | None:
    """Return compute-time cap for attack-path enumeration.

    Default behavior is controlled by `ATTACK_PATHS_COMPUTE_DEFAULT_MAX`.
    `None` means unlimited (legacy behavior).

    Env overrides:
        ADSCAN_ATTACK_PATHS_COMPUTE_MAX:
            - positive int => hard cap
            - 0 / negative => unlimited
    """
    hard_cap_raw = os.getenv("ADSCAN_ATTACK_PATHS_COMPUTE_MAX", "").strip()
    if hard_cap_raw:
        try:
            hard_cap = int(hard_cap_raw)
            if hard_cap <= 0:
                return None
            return hard_cap
        except ValueError:
            pass

    _ = max_display
    if ATTACK_PATHS_COMPUTE_DEFAULT_MAX is None:
        return None
    return max(1, int(ATTACK_PATHS_COMPUTE_DEFAULT_MAX))


def _summarize_high_value_session_paths(
    *,
    shell: BloodHoundShell,
    domain: str,
    paths: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, set[str]]], int]:
    """Return host->segmented-users session map and valid edge count for HasSession paths."""
    host_to_users: dict[str, dict[str, set[str]]] = {}
    valid_edges = 0

    for entry in paths:
        if not isinstance(entry, dict):
            continue
        nodes = entry.get("nodes")
        rels = entry.get("rels")
        if (
            not isinstance(nodes, list)
            or len(nodes) < 2
            or not isinstance(rels, list)
            or not rels
            or str(rels[0] or "").strip().lower() != "hassession"
        ):
            continue

        host_node = nodes[0] if isinstance(nodes[0], dict) else None
        user_node = nodes[1] if isinstance(nodes[1], dict) else None
        if not isinstance(host_node, dict) or not isinstance(user_node, dict):
            continue

        host_name = str(
            host_node.get("label")
            or host_node.get("name")
            or (
                host_node.get("properties", {}).get("name")
                if isinstance(host_node.get("properties"), dict)
                else ""
            )
            or ""
        ).strip()
        user_name = str(
            user_node.get("label")
            or user_node.get("name")
            or (
                user_node.get("properties", {}).get("name")
                if isinstance(user_node.get("properties"), dict)
                else ""
            )
            or ""
        ).strip()
        if not host_name or not user_name:
            continue

        normalized_user = normalize_samaccountname(user_name)
        identity_record = (
            get_identity_risk_record(
                shell,
                domain=domain,
                samaccountname=normalized_user,
            )
            if normalized_user
            else None
        )
        bucket = "control_exposure"
        if isinstance(identity_record, dict):
            if bool(identity_record.get("has_direct_domain_control")):
                bucket = "direct_domain_control"
            elif bool(identity_record.get("is_domain_compromise_enabler")):
                bucket = "domain_compromise_enabler"
            elif bool(identity_record.get("has_high_impact_privilege")):
                bucket = "high_impact_privilege"
            elif bool(identity_record.get("is_control_exposed")):
                bucket = "control_exposure"

        valid_edges += 1
        host_bucket = host_to_users.setdefault(
            host_name,
            {
                "direct_domain_control": set(),
                "domain_compromise_enabler": set(),
                "high_impact_privilege": set(),
                "control_exposure": set(),
            },
        )
        host_bucket.setdefault(bucket, set()).add(user_name)

    return host_to_users, valid_edges


def _print_high_value_session_summary(
    shell: BloodHoundShell,
    *,
    domain: str,
    paths: list[dict[str, Any]],
    max_hosts: int = 20,
    max_users_per_host: int = 4,
) -> None:
    """Render a focused UX summary for control-exposed session relationships."""
    host_to_users, valid_edges = _summarize_high_value_session_paths(
        shell=shell,
        domain=domain,
        paths=paths,
    )
    if not host_to_users or valid_edges <= 0:
        return

    marked_domain = mark_sensitive(domain, "domain")
    total_hosts = len(host_to_users)
    direct_domain_control_users = {
        user
        for users in host_to_users.values()
        for user in users.get("direct_domain_control", set())
    }
    domain_compromise_enabler_users = {
        user
        for users in host_to_users.values()
        for user in users.get("domain_compromise_enabler", set())
    }
    high_impact_privilege_users = {
        user
        for users in host_to_users.values()
        for user in users.get("high_impact_privilege", set())
    }
    control_exposure_users = {
        user
        for users in host_to_users.values()
        for user in users.get("control_exposure", set())
    }
    total_users = (
        len(direct_domain_control_users)
        + len(domain_compromise_enabler_users)
        + len(high_impact_privilege_users)
        + len(control_exposure_users)
    )

    # Single composed panel: header KPIs + canonical compromise-class
    # KPI panel + per-host detail table land in one ``Panel(Group(...))``
    # so the renderer creates a single spatial unit (no nested cards, no
    # stacked borders). The TUI design rule: borders serve content, not
    # ego — collapse stacks once they read as one story.
    border, glyph, _ = _severity_palette(
        critical_hit=bool(direct_domain_control_users),
        high_hit=bool(domain_compromise_enabler_users or high_impact_privilege_users),
        has_findings=valid_edges > 0,
    )

    header_lines = Text()
    header_lines.append("Domain  ", style="dim")
    header_lines.append(f"{marked_domain}\n", style=f"bold {ADSCAN_PRIMARY}")
    header_lines.append(
        "Active sessions from control-exposed identities have been observed on the hosts below.\n",
        style="default",
    )
    header_lines.append("Relationships  ", style="dim")
    header_lines.append(f"{valid_edges:>4d}", style="bold")
    header_lines.append("    ", style="default")
    header_lines.append("Hosts  ", style="dim")
    header_lines.append(f"{total_hosts:>4d}", style="bold")
    header_lines.append("    ", style="default")
    header_lines.append("Identities  ", style="dim")
    header_lines.append(f"{total_users:>4d}", style="bold")

    # Tier 0 Exposure rollup — accounts that sit inside the Tier 0 containment
    # boundary (direct domain control, or one-technique escalation-capable).
    # This is the SSOT "validated path to Tier 0" bucket the client report and
    # web both headline, surfaced here so the operator reads the same rollup.
    tier0_exposed = (
        len(direct_domain_control_users)
        + len(domain_compromise_enabler_users)
        + len(high_impact_privilege_users)
    )
    if tier0_exposed:
        header_lines.append("    ", style="default")
        header_lines.append("Tier 0 Exposure  ", style="dim")
        header_lines.append(
            f"{tier0_exposed:>4d}",
            style=f"bold {COLOR_CRIMSON}"
            if direct_domain_control_users
            else f"bold {COLOR_AMBER}",
        )

    # Canonical compromise-class KPI panel (CLAUDE.md § Nomenclature
    # Standard). Legacy ``high_impact_privilege`` folds into Privileged
    # Escalator. Compromise Enabler is path-derived, not surfaced here.
    kpi_panel = render_kpi_panel(
        domain_breaker=(len(direct_domain_control_users), 0),
        privileged_escalator=(
            len(domain_compromise_enabler_users) + len(high_impact_privilege_users),
            0,
        ),
        compromise_enabler=(0, 0),
        title=f"Compromise Exposure  ·  {marked_domain}",
    )

    table = Table(
        title=(
            f"Sessions by Host  (showing {min(total_hosts, max_hosts)} of {total_hosts})"
            if total_hosts > max_hosts
            else "Sessions by Host"
        ),
        title_style="bold",
        show_header=True,
        header_style="dim bold",
        box=SIMPLE,
        pad_edge=False,
        padding=(0, 1),
    )
    table.add_column("Host", overflow="fold")
    table.add_column("Direct", justify="right")
    table.add_column("Enabler", justify="right")
    table.add_column("Exposed", justify="right")
    table.add_column("Sample identities", overflow="fold")

    ordered = sorted(
        host_to_users.items(),
        key=lambda item: (
            -len(item[1].get("direct_domain_control", set())),
            -len(item[1].get("domain_compromise_enabler", set())),
            -(
                len(item[1].get("high_impact_privilege", set()))
                + len(item[1].get("control_exposure", set()))
            ),
            item[0].lower(),
        ),
    )
    for rank, (host, segmented_users) in enumerate(ordered[:max_hosts]):
        direct_users = segmented_users.get("direct_domain_control", set())
        enabler_users = segmented_users.get("domain_compromise_enabler", set())
        other_users = segmented_users.get(
            "high_impact_privilege", set()
        ) | segmented_users.get("control_exposure", set())
        user_list = sorted(
            direct_users | enabler_users | other_users,
            key=str.lower,
        )
        shown = user_list[:max_users_per_host]
        users_text = ", ".join(mark_sensitive(u, "user") for u in shown)
        extra = len(user_list) - len(shown)
        if extra > 0:
            users_text = f"{users_text}  (+{extra} more)"
        # Top-ranked host gets a star glyph so the eye lands on the
        # worst offender without us reordering the table or using
        # side-stripe borders (banned by impeccable).
        host_label = mark_sensitive(host, "hostname")
        host_cell = Text(
            f"* {host_label}" if rank == 0 and direct_users else f"  {host_label}",
            style=f"bold {COLOR_CRIMSON}"
            if direct_users
            else (f"bold {COLOR_AMBER}" if enabler_users else "default"),
        )
        table.add_row(
            host_cell,
            _count_cell(len(direct_users), hot=True, severity=COLOR_CRIMSON),
            _count_cell(len(enabler_users), hot=True, severity=COLOR_AMBER),
            _count_cell(len(other_users), hot=False, severity=COLOR_STEEL),
            Text(users_text, style="default"),
        )

    next_action = Text()
    next_action.append("Next:  ", style="dim")
    if direct_domain_control_users:
        next_action.append(
            "isolate the direct-control identities first; rotate their secrets and review session origin hosts before tackling enabler accounts.",
            style="default",
        )
    elif domain_compromise_enabler_users or high_impact_privilege_users:
        next_action.append(
            "rotate enabler-tier secrets and audit logon hosts; these accounts shorten the path to Tier 0.",
            style="default",
        )
    else:
        next_action.append(
            "review session locations of the listed identities and reduce standing access.",
            style="default",
        )

    # Compact tiering legend (axis 1) from the SSOT glossary, so the operator
    # reads the same Privilege Tier definitions the client deliverable carries.
    legend_panel = render_tiering_legend()

    panel = Panel(
        Group(
            header_lines,
            Text(""),
            kpi_panel,
            Text(""),
            table,
            Text(""),
            next_action,
            Text(""),
            legend_panel,
        ),
        title=Text(f" {glyph}  Control-Exposure Session Exposure ", style="bold"),
        title_align="left",
        border_style=border,
        box=ROUNDED,
        padding=(1, 2),
    )
    _get_console().print(panel)


def _severity_palette(
    *,
    critical_hit: bool,
    high_hit: bool,
    has_findings: bool,
) -> tuple[str, str, str]:
    """Return ``(border_style, glyph, posture_style)`` for a tiered finding.

    Single source of truth so the four hygiene panels do not drift in
    their severity-to-color mapping. Pairing color with a glyph (``!!``,
    ``!``, ``?``, ``ok``) keeps the panels usable under ``NO_COLOR`` and
    in 16-ANSI terminals, per the TUI design rule that color must never
    be the only carrier of meaning.
    """
    if critical_hit:
        return COLOR_CRIMSON, "!!", f"bold {COLOR_CRIMSON}"
    if high_hit:
        return COLOR_AMBER, "!", f"bold {COLOR_AMBER}"
    if has_findings:
        return COLOR_STEEL, "?", f"bold {COLOR_STEEL}"
    return COLOR_SAGE, "ok", f"bold {COLOR_SAGE}"


def _count_cell(value: int, *, hot: bool, severity: str) -> Text:
    """Right-aligned count cell. Number first, color reserved for severity.

    Zero counts are muted regardless of the column severity so the eye
    skips them; non-zero counts only colorise when the cell represents
    an actionable severity tier. Pure logic-free presentation helper.
    """
    if value <= 0:
        return Text(f"{value:>4d}", style=COLOR_MUTED)
    if not hot:
        return Text(f"{value:>4d}", style="bold")
    return Text(f"{value:>4d}", style=f"bold {severity}")


def _ranked_priority_cell(
    *,
    rank: str,
    label: str,
    glyph: str,
    color: str,
    is_top: bool,
) -> Text:
    """Format the leftmost ranking column for hygiene segmentation tables.

    ``rank`` carries the canonical P0/P1/P2 token (keeps machine-readable
    keys intact for grep). ``glyph`` and ``color`` encode the same
    severity in a NO_COLOR-safe pair. ``is_top`` adds a star prefix on
    the highest active tier so the eye lands there first without us
    having to reorder rows or resort to side-stripe borders.
    """
    star = "* " if is_top else "  "
    return Text(
        f"{star}{glyph} {rank}  {label}", style=f"bold {color}" if is_top else color
    )


class BloodHoundShell(Protocol):
    """Protocol for shell methods needed by BloodHound CLI helpers."""

    def _get_graph_service(self) -> object: ...

    def _filter_aces_by_adcs_requirement(
        self, aces: list[dict]
    ) -> tuple[list[dict], list[dict]]: ...

    def _extract_acl_header(self, output: str) -> str | None: ...

    def _format_acl_block(self, ace_block: dict) -> str: ...

    @property
    def domains_data(self) -> dict: ...

    @property
    def console(self) -> Any: ...

    def _get_workspace_cwd(self) -> str: ...

    def _ensure_kerberos_environment_for_command(
        self,
        target_domain: str,
        auth_domain: str,
        username: str,
        command: str,
    ) -> bool: ...

    def _questionary_select(
        self, title: str, options: list[str], default_idx: int = 0
    ) -> int | None: ...

    def _questionary_checkbox(
        self,
        title: str,
        options: list[str],
        default_values: list[str] | None = None,
    ) -> list[str] | None: ...

    def dns_find_dcs(self, target_domain: str) -> None: ...

    @property
    def domains(self) -> list[str]: ...

    @property
    def domains_dir(self) -> str: ...

    @property
    def domain(self) -> str | None: ...

    def run_command(
        self, command: str, timeout: int | None = None, cwd: str | None = None
    ) -> Any: ...

    def _write_user_list_file(
        self, domain: str, filename: str, users: list[str]
    ) -> str: ...

    def _write_domain_list_file(
        self, domain: str, filename: str, values: list[str]
    ) -> str: ...

    def check_high_value(
        self, domain: str, username: str, *, logging: bool = True
    ) -> bool: ...

    def _postprocess_user_list_file(
        self,
        domain: str,
        filename: str,
        *,
        trigger_followups: bool = True,
        source: str | None = None,
    ) -> None: ...

    def _process_computers_list(
        self, domain: str, comp_file: str, computers: list[str]
    ) -> None: ...

    def _display_items(self, items: list[str], label: str) -> None: ...

    def update_report_field(self, domain: str, key: str, value: Any) -> None: ...

    def is_computer_dc(self, domain: str, target_host: str) -> bool: ...

    @property
    def auto(self) -> bool: ...

    @property
    def type(self) -> str: ...

    @property
    def license_mode(self) -> str: ...

    def do_check_dns(self, domain: str) -> bool: ...

    def do_update_resolv_conf(self, resolv_conf_line: str) -> None: ...

    def convert_hostnames_to_ips_and_scan(
        self, domain: str, computers_file: str, nmap_dir: str
    ) -> None: ...

    def enable_user(
        self, domain: str, username: str, password: str, target_username: str
    ) -> bool: ...

    def exploit_force_change_password(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
    ) -> bool: ...

    def exploit_generic_all_user(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        *,
        prompt_for_password_fallback: bool = True,
        prompt_for_user_privs_after: bool = True,
        prompt_for_method_choice: bool = True,
    ) -> bool: ...

    def exploit_control_computer_object(
        self,
        domain: str,
        username: str,
        password: str,
        target_computer: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
        prompt_for_method_choice: bool = True,
    ) -> bool: ...

    def exploit_write_spn(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
    ) -> bool: ...

    def exploit_generic_all_ou(
        self,
        domain: str,
        username: str,
        password: str,
        target_ou: str,
        target_domain: str,
        *,
        followup_after: bool = True,
    ) -> bool: ...

    def exploit_add_member(
        self,
        domain: str,
        username: str,
        password: str,
        target_group: str,
        new_member: str,
        target_domain: str,
        *,
        enumerate_aces_after: bool = True,
    ) -> bool: ...

    def exploit_gmsa_account(
        self,
        domain: str,
        username: str,
        password: str,
        target_account: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
    ) -> bool: ...

    def exploit_laps_password(
        self,
        domain: str,
        username: str,
        password: str,
        target_computer: str,
        target_domain: str,
        *,
        prompt_for_user_privs_after: bool = True,
    ) -> bool: ...

    def exploit_write_dacl(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        target_type: str,
        *,
        followup_after: bool = True,
    ) -> bool: ...

    def exploit_write_owner(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: str,
        target_domain: str,
        target_type: str,
        *,
        followup_after: bool = True,
    ) -> bool: ...

    def dcsync(
        self,
        domain: str,
        username: str,
        password: str,
        target_domain: str | None = None,
    ) -> None: ...


def _certipy_relation_template_tag(relation: str) -> str:
    """Normalize a BH ESC relation to the base Certipy vulnerability tag."""
    rel_upper = str(relation or "").strip().upper()
    if not rel_upper.startswith("ADCSESC"):
        return ""
    esc_tag = rel_upper.replace("ADCS", "", 1)
    if re.fullmatch(r"ESC\d+[A-Z]", esc_tag):
        return esc_tag[:-1]
    return esc_tag


def _has_certipy_display_notes(note: object) -> bool:
    """Return True when a relation note already carries template or CA display data."""
    if not isinstance(note, dict):
        return False
    return bool(
        note.get("enterpriseca_name")
        or note.get("enterpriseca")
        or note.get("template")
        or note.get("templates")
        or note.get("templates_summary")
    )


def _summarize_adcs_detector_path_signatures(
    paths: list[dict[str, Any]],
) -> set[str]:
    """Collapse ADCS path output into stable detector-parity signatures."""
    signatures: set[str] = set()
    for entry in paths:
        if not isinstance(entry, dict):
            continue
        nodes = entry.get("nodes") if isinstance(entry.get("nodes"), list) else []
        rels = entry.get("rels") if isinstance(entry.get("rels"), list) else []
        notes_by_relation_index = (
            entry.get("notes_by_relation_index")
            if isinstance(entry.get("notes_by_relation_index"), dict)
            else {}
        )
        if len(nodes) < 2 or not rels:
            continue
        relation_names = []
        for rel in rels:
            if isinstance(rel, dict):
                relation_names.append(
                    str(
                        rel.get("type")
                        or rel.get("label")
                        or rel.get("kind")
                        or rel.get("name")
                        or ""
                    )
                )
            else:
                relation_names.append(str(rel))
        for rel_idx, rel in enumerate(relation_names):
            if rel_idx + 1 >= len(nodes):
                break
            rel_upper = str(rel or "").strip().upper()
            if not rel_upper.startswith("ADCSESC"):
                continue
            left = _bloodhound_node_display_label(nodes[rel_idx])
            right = _bloodhound_node_display_label(nodes[rel_idx + 1])
            note = notes_by_relation_index.get(rel_idx)
            note_dict = note if isinstance(note, dict) else None
            display_right = _canonicalize_adcs_detector_parity_target(
                relation=rel_upper,
                note=note_dict,
                fallback_target=right,
            )
            signatures.add(f"{left} -> {rel_upper} -> {display_right}")
    return signatures


def _canonicalize_adcs_detector_parity_target(
    *,
    relation: str,
    note: dict[str, Any] | None,
    fallback_target: str,
) -> str:
    """Normalize ADCS display targets so parity compares semantics, not summaries."""
    relation_upper = str(relation or "").strip().upper()
    if relation_upper in {"ADCSESC8", "ADCSESC11", "ADCSESC6A", "ADCSESC7"}:
        ca_name = str(
            (note or {}).get("enterpriseca_name")
            or (note or {}).get("enterpriseca")
            or ""
        ).strip()
        if ca_name:
            return ca_name

    if relation_upper == "ADCSESC3":
        return "ESC3_TEMPLATE_SCOPE"

    return resolve_adcs_display_target(
        relation_upper,
        note,
        fallback_target=fallback_target,
    )


def _load_writable_user_attribute_discovery(
    shell: BloodHoundShell,
    *,
    target_domain: str,
    graph: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Load custom writable-attribute attack steps discovered via LDAP ACL parsing."""
    paths: list[dict[str, Any]] = []
    try:
        from adscan_internal.services.attack_graph_service import (
            get_writable_user_attribute_paths,
        )

        paths = get_writable_user_attribute_paths(shell, target_domain, graph=graph)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[writable-attrs] Writable-attribute discovery load failed: {exc}"
        )
    return paths


def _load_rodc_prp_control_discovery(
    shell: BloodHoundShell,
    *,
    target_domain: str,
    graph: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Load custom delegated RODC PRP control attack steps discovered via LDAP ACL parsing."""
    paths: list[dict[str, Any]] = []
    try:
        from adscan_internal.services.attack_graph_service import (
            get_rodc_prp_control_paths,
        )

        paths = get_rodc_prp_control_paths(shell, target_domain, graph=graph)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[rodc-prp] Delegated RODC PRP discovery load failed: {exc}")
    return paths


def run_enumerate_user_aces(shell: BloodHoundShell, args: str) -> None:
    """Parse arguments and initiate user ACE enumeration.

    Mirrors the legacy ``do_enumerate_user_aces`` entrypoint but keeps argument
    parsing and CLI usage/help text outside of `adscan.py`.
    """
    parts = args.split()
    if len(parts) != 3:
        shell.console.print("Usage: enumerate_user_aces <domain> <user> <password>")  # type: ignore[attr-defined]
        return
    domain, username, password = parts
    shell.ask_for_enumerate_user_aces(domain, username, password)  # type: ignore[attr-defined]


def run_attack_paths(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    max_depth: int = 6,  # requested actionable-edge budget; bounded by _effective_max_depth (user+all caps at 6)
    build_only: bool = False,
) -> None:
    """Enumerate theoretical attack steps from low-priv users.

    Today, this phase focuses on ACL/ACE-style effective relationships derived
    from group membership + rights edges in BloodHound CE. The resulting graph
    is then used to compute maximal attack paths for CLI display.
    """
    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    print_info_debug(
        "[attack_paths] Native graph enabled; delegating legacy "
        "bloodhound_attack_paths entrypoint to local attack graph summaries."
    )
    run_show_attack_paths(
        shell,
        target_domain,
        start_user="owned",
        max_display=20,
        max_depth=max_depth,
        target="all",
        target_mode="object",
        display_friendly=True,
        allow_execution=not build_only,
    )
    return


def run_cross_domain_attack_paths(
    shell: "BloodHoundShell",
    domains: list[str],
    *,
    max_depth: int = 6,  # requested actionable-edge budget; bounded by _effective_max_depth caps
) -> None:
    """Run cross-domain attack path discovery using a merged multi-domain graph.

    Called after all per-domain Phase 2 builds are complete so every
    attack_graph.json is fully populated. Merges all graphs so multi-hop
    paths like USER@A → pivot → USER@B → escalate → DA@A are discoverable.

    Args:
        shell: Shell context with domains_data, credential store, and workspace.
        domains: In-scope domains ordered with the trust source domain first.
        max_depth: Maximum edge depth for path computation.
    """
    from adscan_internal.services.attack_graph_service import (
        get_attack_path_owned_principal_labels,
        get_attack_path_summaries,
        ATTACK_PATHS_MAX_DEPTH_USER,
    )
    from adscan_internal.cli.attack_path_execution import (
        offer_attack_paths_with_non_high_value_fallback,
        persist_attack_path_snapshot,
    )

    reachable = [d for d in domains if d]
    if not reachable:
        return

    # Header — inform user this is a merged cross-domain pass
    print_operation_header(
        "Cross-Domain Attack Paths",
        details={
            "Domains": ", ".join(mark_sensitive(d, "domain") for d in reachable),
            "Mode": "merged graph",
            "Depth": str(max(ATTACK_PATHS_MAX_DEPTH_USER, max_depth)),
        },
        icon="🌐",
    )

    # Collect owned principals from ALL in-scope domains.
    all_owned: list[str] = []
    for domain in reachable:
        owned = get_attack_path_owned_principal_labels(
            shell,
            domain,
            include_trusted_domains=True,
        )
        all_owned.extend(owned)
    all_owned = sorted(set(all_owned))

    primary = reachable[0]
    marked_primary = mark_sensitive(primary, "domain")

    if not all_owned:
        print_info_verbose(
            f"[cross-domain] no owned principals found across {len(reachable)} domain(s); "
            f"falling back to domain-wide summaries for {marked_primary}"
        )
        summaries = get_attack_path_summaries(shell, primary)  # pylint: disable=missing-kwoa
        if summaries:
            try:
                persist_attack_path_snapshot(shell, primary, summaries)  # pylint: disable=too-many-function-args,missing-kwoa
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        return

    marked_count = len(all_owned)
    marked_domain_count = len(reachable)
    print_info(
        f"Searching cross-domain attack paths from {marked_count} owned principal(s) "
        f"across {marked_domain_count} domain(s)"
    )

    try:
        offer_attack_paths_with_non_high_value_fallback(
            shell,
            primary,
            start="owned",
            max_depth=max(ATTACK_PATHS_MAX_DEPTH_USER, max_depth),
            max_display=20,
            target="all",
            target_mode="object",
            display_friendly=True,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(f"Cross-domain attack path calculation failed: {exc}")


def persist_bloodhound_membership_snapshot(
    shell: BloodHoundShell, target_domain: str
) -> tuple[int, int, int]:
    """Persist direct BloodHound MemberOf relationships to `memberships.json`.

    This snapshot belongs to Phase 1 domain inventory because it captures static
    domain membership state alongside users, computers and LAPS coverage.
    """

    print_info_debug(
        "[native-graph] Membership snapshot already persisted by native collection; "
        "skipping BloodHound CE relationship enrichment."
    )
    return 0, 0, 0

    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return 0, 0, 0

    service = shell._get_graph_service()
    client = getattr(service, "client", None)
    execute_query = getattr(client, "execute_query", None)
    if not callable(execute_query):
        print_info_debug(
            "[bloodhound] Membership snapshot skipped: CE client unavailable."
        )
        return 0, 0, 0

    user_query = f"""
    MATCH p=(u:User)-[:MemberOf]->(g:Group)
    WHERE toLower(coalesce(u.name, "")) ENDS WITH toLower('@{target_domain}')
    RETURN p
    """
    computer_query = f"""
    MATCH p=(c:Computer)-[:MemberOf]->(g:Group)
    WHERE toLower(coalesce(c.domain, "")) = toLower('{target_domain}')
    RETURN p
    """
    group_query = f"""
    MATCH p=(g:Group)-[:MemberOf]->(pg:Group)
    WHERE toLower(coalesce(g.name, "")) ENDS WITH toLower('@{target_domain}')
    RETURN p
    """

    from datetime import datetime, timezone
    from adscan_internal.services.attack_graph_service import add_bloodhound_path_edges
    from adscan_internal.workspaces import domain_subpath, write_json_file

    membership_graph: dict[str, object] = {
        "domain": target_domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": "membership-1.0",
        "nodes": {},
        "edges": [],
        "version": 2,
    }

    def _append_graph_data(graph_data: dict[str, object], *, label: str) -> int:
        if not isinstance(graph_data, dict):
            return 0
        nodes_map = graph_data.get("nodes", {})
        edges = graph_data.get("edges", [])
        if not isinstance(nodes_map, dict) or not isinstance(edges, list):
            return 0
        print_info_debug(
            f"[bloodhound] Membership snapshot {label} nodes={len(nodes_map)} edges={len(edges)}"
        )

        def _lookup_node(key: object) -> dict | None:
            if key in nodes_map:
                node = nodes_map.get(key)
                return node if isinstance(node, dict) else None
            str_key = str(key)
            node = nodes_map.get(str_key)
            return node if isinstance(node, dict) else None

        added = 0
        skipped_missing_nodes = 0
        missing_examples: list[dict[str, object]] = []
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            relation = edge.get("label") or edge.get("kind") or ""
            if str(relation) != "MemberOf":
                continue
            source = edge.get("source")
            target = edge.get("target")
            if not source or not target:
                continue
            src_node = _lookup_node(source)
            dst_node = _lookup_node(target)
            if not isinstance(src_node, dict) or not isinstance(dst_node, dict):
                skipped_missing_nodes += 1
                if len(missing_examples) < 3:
                    missing_examples.append(
                        {
                            "source": source,
                            "target": target,
                            "source_type": type(source).__name__,
                            "target_type": type(target).__name__,
                            "label": relation,
                        }
                    )
                continue
            add_bloodhound_path_edges(
                membership_graph,
                nodes=[src_node, dst_node],
                relations=["MemberOf"],
                status="discovered",
                edge_type="membership_snapshot",
                log_creation=False,
                shell=shell,
            )
            added += 1

        if skipped_missing_nodes:
            print_info_debug(
                f"[bloodhound] Membership snapshot {label} skipped {skipped_missing_nodes} "
                "edges due to missing nodes."
            )
            if missing_examples:
                print_info_debug(
                    f"[bloodhound] Membership snapshot {label} missing node examples: "
                    f"{missing_examples}"
                )
        return added

    user_edges = 0
    computer_edges = 0
    group_edges = 0
    try:
        user_graph = client.execute_query_with_relationships(user_query)
        user_edges = _append_graph_data(user_graph, label="user")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    try:
        computer_graph = client.execute_query_with_relationships(computer_query)
        computer_edges = _append_graph_data(computer_graph, label="computer")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    try:
        group_graph = client.execute_query_with_relationships(group_query)
        group_edges = _append_graph_data(group_graph, label="group")
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)

    workspace_cwd = (
        shell._get_workspace_cwd()
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", os.getcwd())
    )
    output_path = domain_subpath(
        workspace_cwd, shell.domains_dir, target_domain, "memberships.json"
    )
    write_json_file(output_path, membership_graph)
    return user_edges, group_edges, computer_edges


def run_show_attack_paths(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    start_user: str | None = None,
    start_users: list[str] | None = None,
    index: int | None = None,
    max_display: int = 10,
    max_depth: int = ATTACK_PATHS_MAX_DEPTH_USER,
    target: str = "highvalue",
    target_mode: str = "object",
    display_friendly: bool | None = None,
    allow_execution: bool = True,
    max_path_steps: int | None = None,
    no_cache: bool = False,
    keep_longest: bool = False,
) -> None:
    """Show attack paths and optionally a detailed path.

    ``keep_longest`` only affects the ``domain`` scope (no explicit start user /
    ``owned``): when False (default) the listing shows the most direct route to
    domain compromise; when True it shows the holistic longest kill chain.
    """
    from adscan_internal.services.attack_graph_service import (
        get_attack_paths_cache_stats,
        get_attack_path_summaries,
        get_owned_domain_usernames_for_attack_paths,
    )
    from adscan_internal.services.membership_snapshot import (
        get_membership_snapshot_cache_stats,
    )
    from adscan_internal.services.cache_metrics import diff_stats
    from adscan_internal.rich_output import (
        print_attack_path_detail,
        print_attack_paths_summary,
    )
    from adscan_internal.cli.attack_path_execution import offer_attack_path_execution

    def _maybe_offer_execution(summary: dict[str, Any]) -> bool:
        # No TTY check here. ``_handle_path_detail`` is only reached when
        # the operator either picked a path from the questionary menu
        # (proves interactivity) or explicitly passed
        # ``--attack-path-index N`` (clear intent). The previous
        # ``sys.stdin.isatty()`` check was redundant AND wrong under
        # prompt_toolkit-managed shells where stdin is wrapped and
        # ``isatty()`` returns False even though the operator IS sitting
        # at an interactive terminal. ``offer_attack_path_execution`` is
        # never reached from ``adscan ci`` (CI takes the non-interactive
        # branch in ``_interactive_detail_loop`` and calls
        # ``offer_attack_paths_for_execution_summaries`` instead), so
        # there is no risk of ``Confirm.ask`` blocking a non-interactive
        # run via this code path.
        return offer_attack_path_execution(
            shell,
            domain=target_domain,
            summary=summary,
            allowed=execution_allowed_for_scope,
        )

    def _interactive_detail_loop(
        path_refs: list[dict[str, Any]],
    ) -> None:
        """Interactive selection loop over attack paths.

        Share-credential-hunt selection used to live in this menu but moved
        to its own dedicated phase ("SMB Share Exposure", after Password
        Spraying) so the attack-paths UX stays focused on path execution.
        """
        from adscan_internal.interaction import is_non_interactive as _is_non_interactive

        is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
        _non_interactive = is_ci or not sys.stdin.isatty() or _is_non_interactive(shell)

        # Share-credential hunt moved to its own phase (Phase 5: Share
        # Credential Hunt). The legacy helpers `_is_share_only`,
        # `_build_deduped_shares`, `_access_str`, `_SHARE_REL_KEYS`, and
        # `_ACCESS_LABELS` that used to live here were removed with that
        # migration — share rows no longer appear in the attack-paths menu.

        def _path_type_tag(path: dict[str, Any]) -> str:
            cls = (
                str(
                    path.get("outcome_class")
                    or path.get("compromise_class")
                    or path.get("target_outcome")
                    or ""
                )
                .strip()
                .lower()
            )
            if cls == "direct_compromise" or "domain_breaker" in cls:
                return "Domain Control"
            if cls == "tier0_foothold":
                return "T0 Foothold"
            if (
                cls in {"followup_terminal", "graph_extension"}
                or "privileged_escalator" in cls
            ):
                return "Escalation"
            if cls == "pivot":
                return "Pivot"
            return "Path"

        def _path_source_target(path: dict[str, Any]) -> tuple[str, str]:
            nodes = path.get("nodes") if isinstance(path.get("nodes"), list) else []
            source = str(path.get("source") or (nodes[0] if nodes else "") or "")
            target = str(path.get("target") or (nodes[-1] if nodes else "") or "")
            if not source or not target:
                title = str(path.get("title") or "")
                if "->" in title:
                    parts = [p.strip() for p in title.split("->")]
                    source = source or (parts[0] if parts else "")
                    target = target or (parts[-1] if parts else "")
            return source, target

        def _mark_node(name: str) -> str:
            # Strip domain suffix (e.g. @AIS.LOCAL) — domain is shown in panel header.
            display = name.split("@")[0] if "@" in name else name
            if "." in display or display.endswith("$"):
                return mark_sensitive(display, "hostname")
            return mark_sensitive(display, "user")

        def _handle_path_detail(path: dict[str, Any], display_idx: int) -> None:
            print_attack_path_detail(
                target_domain,
                path,
                index=display_idx,
                search_mode_label=summary_search_mode_label,
            )
            _maybe_offer_execution(path)
            # ALWAYS recompute + re-render the attack-paths table after any
            # interaction with a path, regardless of whether execution
            # actually started.  Reasons:
            #   - Execution succeeded → edge status moved to attempted/
            #     exploited and the canonical sort key (status_order)
            #     deprioritises it on the next render.
            #   - Path was blocked + pivot probe ran → new persisted
            #     pivot evidence is consumed by the inference layer and
            #     the annotation now marks every path sharing the same
            #     unreachable target with ``viability_rank=1`` so the
            #     canonical sort buries them.
            #   - User declined / gate refused / inference skipped probe
            #     → no state change, but recomputing keeps the table
            #     consistent with the regla "no priorizar paths ya
            #     ejecutados ni paths con host inalcanzable" on every
            #     menu iteration. The cost is one materialised-cache
            #     hit on the prepared runtime graph; the DFS itself is
            #     bounded by the same depth/scope as the initial run.
            # In CTF AND audit workspaces, once the domain is compromised the
            # owned-scope path list is exhausted — skip the recompute +
            # re-display so the operator lands cleanly on the post-compromise
            # flow without an extra engine-selection prompt or path list.
            # CTF: post-compromise is flags/cleanup. Audit: the holistic
            # remaining-paths view is rendered later from the DOMAIN scope by
            # the "Audit Post-Compromise: Remaining Attack Paths" block in
            # run_enumeration (paths to domain compromise from ANY low-priv,
            # not just from owned users) — re-offering owned-scope paths here
            # would be redundant and misleading.
            _now_pwned = (
                str(
                    getattr(shell, "domains_data", {})
                    .get(target_domain, {})
                    .get("auth")
                    or ""
                )
                .strip()
                .lower()
                == "pwned"
            )
            if _now_pwned and getattr(shell, "type", None) in ("ctf", "audit"):
                return
            # Symmetry with the CI/non-interactive flow: drop every
            # attack-path cache layer before recomputing so the operator
            # sees the freshest possible view of post-execution state.
            # See ``force_fresh_attack_paths_recompute`` docstring for the
            # full rationale on why centralising the invalidation here
            # is load-bearing even though ``save_attack_graph`` already
            # invalidates the cache on every edge write.
            from adscan_internal.services.attack_graph_service import (
                force_fresh_attack_paths_recompute,
            )
            force_fresh_attack_paths_recompute(
                target_domain, reason="post_execution_refresh_interactive"
            )
            path_refs[:] = _compute_paths()
            if path_refs:
                # Annotate before sort/render so the canonical sort key
                # reads ``meta["execution_target_viability_status"]``
                # (now updated with the latest pivot-probe evidence).
                # Without this, paths sharing the just-confirmed
                # unreachable target would re-surface at the top.
                try:
                    from adscan_internal.cli.attack_path_execution import (
                        _annotate_execution_readiness as _annotate,
                    )
                    path_refs[:] = _annotate(
                        shell,
                        domain=target_domain,
                        summaries=path_refs,
                        context_username=None,
                        context_password=None,
                    )
                except Exception as _annotate_exc:
                    telemetry.capture_exception(_annotate_exc)
                _sorted = print_attack_paths_summary(
                    target_domain,
                    path_refs,
                    max_display=max_display,
                    max_path_steps=max_path_steps,
                    search_mode_label=summary_search_mode_label,
                    show_sections=show_sections,
                )
                if _sorted:
                    path_refs[:] = _sorted

        # `_handle_share_scan` used to live here. The share credential hunt
        # moved to its own dedicated phase (Phase 7: SMB Share Exposure,
        # after Password Spraying), so the attack-paths menu no longer
        # offers it — keeping the UX focused on path execution only.

        attack_paths = path_refs[:max_display]

        while True:
            # ── CI / non-interactive fallback ──────────────────────────────────
            if _non_interactive:
                if not attack_paths:
                    return
                from adscan_internal import print_info_debug as _dbg
                _dbg(
                    f"[attack_paths] non-interactive execution: "
                    f"is_ci={is_ci!r} isatty={sys.stdin.isatty()!r} "
                    f"paths={len(attack_paths)} domain={target_domain}"
                )
                # Use the execution framework that auto-selects and auto-confirms
                # in non-interactive mode, rather than _handle_path_detail which
                # gates on sys.stdin.isatty() and blocks execution in `adscan ci`.
                #
                # ``recompute_summaries`` is the closure that re-runs the
                # original scan with the same scope/principals/depth/target
                # the operator (or ``adscan ci``) invoked. Wiring it here is
                # what stops the infinite re-prompt loop after a successful
                # execution: without it, ``_refresh_summaries`` reuses the
                # closure-captured ``summaries`` list (computed BEFORE the
                # attack ran, with ``status='theoretical'``), the path stays
                # actionable by :func:`_path_is_actionable_for_execution_prompt`,
                # and the loop re-selects the same path forever.
                #
                # Every other caller of ``offer_attack_paths_for_execution_summaries``
                # in ``attack_path_execution.py`` already passes this callback —
                # the CI branch was the only outlier. The structural test in
                # ``tests/unit/cli/test_attack_path_ci_refresh_callback.py``
                # locks the invariant so future regressions fail loud.
                #
                # We intentionally do NOT pass ``execute_only_statuses`` or
                # ``auto_continue_theoretical_in_non_interactive`` here —
                # both are now the canonical defaults inside the function
                # for non-interactive callers (theoretical-only filter,
                # auto-converge when no theoretical remain). Keeping them
                # implicit here makes the policy live in one place and
                # ensures future callers that forget to pass them still
                # inherit the safe behaviour.
                from adscan_internal.cli.attack_path_execution import (
                    offer_attack_paths_for_execution_summaries as _offer_exec,
                )
                _offer_exec(
                    shell,
                    target_domain,
                    summaries=attack_paths,
                    max_display=len(attack_paths),
                    recompute_summaries=_compute_paths,
                )
                return

            # ── Structured questionary menu with sections ──────────────────────
            try:
                import questionary as _q  # type: ignore
                from adscan_core.prompting import questionary_style

                _SEP = "─" * 76
                choices: list[Any] = []

                if attack_paths:
                    choices.append(_q.Separator(f"  Attack Paths  {'─' * 58}"))
                    for i, path in enumerate(attack_paths):
                        source, target = _path_source_target(path)
                        tag = _path_type_tag(path)
                        status = str(path.get("status") or "theoretical")
                        status_suffix = (
                            f"  [{status}]" if status != "theoretical" else ""
                        )
                        label = (
                            f"  {i + 1}.  [{tag}]  "
                            f"{_mark_node(source)} → {_mark_node(target)}{status_suffix}"
                        )
                        choices.append(_q.Choice(title=label, value=f"path:{i}"))

                choices.append(_q.Separator(f"  {_SEP}"))
                choices.append(_q.Choice(title="  Exit", value="exit"))

                result = _q.select(
                    "Select an action:",
                    choices=choices,
                    style=questionary_style(_q),
                ).ask()

                if result is None or result == "exit":
                    return
                if isinstance(result, str) and result.startswith("path:"):
                    idx = int(result.split(":", 1)[1])
                    _handle_path_detail(attack_paths[idx], idx + 1)
                    # CTF and audit: if the execution just compromised the
                    # domain, exit the owned-scope selection loop. The audit
                    # holistic remaining-paths view is rendered later from the
                    # DOMAIN scope by the post-compromise block in
                    # run_enumeration; re-offering owned-scope paths here is
                    # redundant once the domain is owned.
                    _pwned_after = (
                        str(
                            getattr(shell, "domains_data", {})
                            .get(target_domain, {})
                            .get("auth")
                            or ""
                        )
                        .strip()
                        .lower()
                        == "pwned"
                    )
                    if _pwned_after and getattr(shell, "type", None) in ("ctf", "audit"):
                        return
                    continue

            except Exception:
                # ── Plain text fallback (no questionary) ──────────────────────
                flat: list[str] = [
                    f"{i + 1}. [{_path_type_tag(p)}] "
                    + _mark_node(_path_source_target(p)[0])
                    + " → "
                    + _mark_node(_path_source_target(p)[1])
                    for i, p in enumerate(attack_paths)
                ]
                flat.append("0. Exit")

                if hasattr(shell, "_questionary_select"):
                    flat_with_exit = flat[:-1] + ["Exit"]
                    sel = shell._questionary_select("Select an action:", flat_with_exit)
                    if sel is None or sel >= len(flat_with_exit) - 1:
                        return
                    if sel < len(attack_paths):
                        _handle_path_detail(attack_paths[sel], sel + 1)
                        _pwned_after = (
                            str(
                                getattr(shell, "domains_data", {})
                                .get(target_domain, {})
                                .get("auth")
                                or ""
                            )
                            .strip()
                            .lower()
                            == "pwned"
                        )
                        if _pwned_after and getattr(shell, "type", None) in ("ctf", "audit"):
                            return
                    continue

                raw = Prompt.ask("Select (0 to exit)", default="1")
                try:
                    n = int(raw)
                except ValueError:
                    n = 1
                if n <= 0:
                    return
                if 1 <= n <= len(attack_paths):
                    _handle_path_detail(attack_paths[n - 1], n)
                continue

    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    cache_before = get_attack_paths_cache_stats(domain=target_domain)
    membership_cache_before = get_membership_snapshot_cache_stats()

    start_user_norm = (start_user or "").strip().lower()
    # Two-section display (HV first + pivot section) is active when target="all".
    show_sections = target == "all"
    # When show_sections is active the panel header already shows 🎯/⚠ counts,
    # so the "Mode:" label is redundant — suppress it.
    summary_search_mode_label = (
        None
        if show_sections
        else describe_search_mode_label("low_priv")
        if target == "lowpriv"
        else describe_search_mode_label("direct_compromise")
        if str(target_mode or "impact").strip().lower() == "tier0"
        else describe_search_mode_label("followup_terminal")
    )
    domain_auth = (
        str(getattr(shell, "domains_data", {}).get(target_domain, {}).get("auth") or "")
        .strip()
        .lower()
    )
    execution_allowed_for_scope = bool(
        allow_execution and (start_user_norm == "owned" or domain_auth == "pwned")
    )
    max_paths_compute = _resolve_attack_paths_compute_cap(max_display)

    def _sort_paths(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Canonical UX ordering — same single source of truth used by the
        # table renderer and any selector prompt downstream. The canonical
        # key already groups by priority class (Tier 0 → high-value → pivot)
        # before applying choke-point ranking, so sectioned mode does not
        # need a secondary regroup.
        from adscan_internal.rich_output import order_attack_paths_for_display

        return order_attack_paths_for_display(paths)

    def _compute_paths() -> list[dict[str, Any]]:
        if start_user_norm == "owned":
            owned_users = get_owned_domain_usernames_for_attack_paths(
                shell, target_domain
            )
            if not owned_users:
                marked_domain = mark_sensitive(target_domain, "domain")
                print_warning(
                    f"No eligible owned domain users found for {marked_domain}."
                )
                return []
            owned_paths = get_attack_path_summaries(
                shell,
                target_domain,
                scope="owned",
                max_depth=max_depth,
                max_paths=max_paths_compute,
                target=target,
                target_mode=target_mode,
                display_friendly=display_friendly,
                no_cache=no_cache,
            )
            if not owned_paths:
                marked_domain = mark_sensitive(target_domain, "domain")
                scope = (
                    "Tier-0 targets" if target_mode == "tier0" else "high-value targets"
                )
                print_warning(
                    "No attack paths found for owned users in "
                    f"{marked_domain} (users: {len(owned_users)}). "
                    f"Try `attack_paths <domain> owned --all` to include all targets "
                    f"instead of only {scope.lower()}."
                )
                return []
            return _sort_paths(owned_paths)
        if start_users and len(start_users) > 1:
            principal_paths = get_attack_path_summaries(
                shell,
                target_domain,
                scope="principals",
                principals=start_users,
                max_depth=max_depth,
                max_paths=max_paths_compute,
                target=target,
                target_mode=target_mode,
                display_friendly=display_friendly,
                no_cache=no_cache,
            )
            if not principal_paths:
                marked_users = ", ".join(mark_sensitive(u, "user") for u in start_users)
                print_warning(f"No attack paths found for users: {marked_users}.")
            return _sort_paths(principal_paths)
        if start_user:
            user_paths = get_attack_path_summaries(
                shell,
                target_domain,
                scope="user",
                username=start_user,
                max_depth=max_depth,
                max_paths=max_paths_compute,
                target=target,
                target_mode=target_mode,
                display_friendly=display_friendly,
                no_cache=no_cache,
            )
            return _sort_paths(user_paths)
        domain_paths = get_attack_path_summaries(
            shell,
            target_domain,
            scope="domain",
            max_depth=max_depth,
            max_paths=max_paths_compute,
            target=target,
            target_mode=target_mode,
            display_friendly=display_friendly,
            no_cache=no_cache,
            keep_longest=keep_longest,
        )
        return _sort_paths(domain_paths)

    path_refs = _compute_paths()
    cache_after = get_attack_paths_cache_stats(domain=target_domain)
    membership_cache_after = get_membership_snapshot_cache_stats()

    cache_delta = diff_stats(
        before=cache_before,
        after=cache_after,
        keys=("hits", "misses", "stores", "skips", "evictions", "invalidations"),
    )
    snapshot_delta = diff_stats(
        before=membership_cache_before,
        after=membership_cache_after,
        keys=("hits", "misses", "reloads", "loaded"),
    )

    print_info_debug(
        "[attack_paths] cache summary: "
        f"domain={mark_sensitive(target_domain, 'domain')} "
        f"paths_hits={cache_delta['hits']} paths_misses={cache_delta['misses']} "
        f"paths_stores={cache_delta['stores']} paths_skips={cache_delta['skips']} "
        f"paths_evictions={cache_delta['evictions']} paths_invalidations={cache_delta['invalidations']} "
        f"membership_hits={snapshot_delta['hits']} membership_misses={snapshot_delta['misses']} "
        f"membership_reloads={snapshot_delta['reloads']} membership_loaded={snapshot_delta['loaded']}"
    )

    # Share-exposure data is computed and displayed by the dedicated Phase 7
    # "SMB Share Exposure" (see ``share_exposure_phase.run_smb_share_exposure_phase``)
    # rather than mixed into the attack-paths UX. The attack-paths flow
    # now stays focused on path execution only.

    if not path_refs:
        print_warning("No attack paths recorded for this domain.")
        return

    # Annotate execution readiness BEFORE the table sort. The canonical sort
    # key in ``order_attack_paths_for_display`` reads
    # ``meta["execution_target_viability_status"]`` to demote paths whose
    # exec target is unreachable from the current vantage. Without this,
    # the table and the execution-selector below would sort differently —
    # the table would surface unreachable-target paths first while the
    # execution flow correctly buries them.
    try:
        from adscan_internal.cli.attack_path_execution import (
            _annotate_execution_readiness as _annotate,
        )
        path_refs = _annotate(
            shell,
            domain=target_domain,
            summaries=path_refs,
            context_username=None,
            context_password=None,
        )
    except Exception as _annotate_exc:
        telemetry.capture_exception(_annotate_exc)
        # Non-fatal: fall through with un-annotated paths so the table still
        # renders. The viability deboost is lost for this call but the
        # execution-selector will still annotate later.

    # Privilege blast radius: collapse any source+right that fans out over many
    # targets into ONE capability line above the per-path table (the table rows
    # below are unchanged). Presentation-only view over the same materialized
    # graph — see ``attack_fanout_rollup``. Best-effort; never blocks the table.
    try:
        from adscan_internal.cli.post_scan_suggestions import build_recap_fanout_steps
        from adscan_internal.cli.widgets.scan_recap import (
            render_fanout_capability_lines,
        )
        from rich.console import Group

        _fanout_steps = build_recap_fanout_steps(shell, target_domain, max_steps=5)
        _fanout_lines = render_fanout_capability_lines(_fanout_steps, with_header=False)
        if _fanout_lines:
            print_panel(
                Group(*_fanout_lines),
                title="[bold]Privilege blast radius[/]",
                border_style=ADSCAN_PRIMARY,
                title_align="left",
                padding=(1, 2),
            )
    except Exception as _fanout_exc:  # noqa: BLE001 - never block the listing
        telemetry.capture_exception(_fanout_exc)

    _sorted_refs = print_attack_paths_summary(
        target_domain,
        path_refs,
        max_display=max_display,
        max_path_steps=max_path_steps,
        search_mode_label=summary_search_mode_label,
        show_sections=show_sections,
    )

    # Index-based selection must address the same canonical UX order as the
    # rendered table; otherwise a user-provided `--attack-path-index N` would
    # pick a different path than the one shown at row N.
    indexable_refs = _sorted_refs or path_refs

    if index is None:
        _interactive_detail_loop(indexable_refs)
        return

    if index < 1 or index > len(indexable_refs):
        print_warning("Invalid path index.")
        return

    selected = indexable_refs[index - 1]
    print_attack_path_detail(
        target_domain,
        selected,
        index=index,
        search_mode_label=summary_search_mode_label,
    )
    _maybe_offer_execution(selected)


def run_show_attack_steps(
    shell: BloodHoundShell,
    target_domain: str,
    *,
    start_user: str | None = None,
    max_display: int = 10,
    relation_filter: str | None = None,
) -> None:
    """Show raw attack-graph steps (edges) for a domain (optionally for one user)."""
    from adscan_internal.rich_output import (
        print_attack_steps_summary,
        print_error,
        print_warning,
    )
    from adscan_internal.rich_output import mark_sensitive
    from adscan_internal.services.attack_graph_service import (
        compute_display_steps_for_domain,
    )

    def _render_local_cred_domain_reuse_clusters(
        *,
        graph: dict[str, Any],
        relation_terms: set[str] | None,
    ) -> None:
        """Render compact summary for LocalCredToDomainReuse clusters."""
        if start_user:
            return
        if relation_terms and not (
            {"localcredtodomainreuse", "localcredreusesource"} & relation_terms
        ):
            return

        nodes = graph.get("nodes")
        edges = graph.get("edges")
        if not isinstance(nodes, dict) or not isinstance(edges, list):
            return

        def _node_label(node_id: str) -> str:
            node = nodes.get(node_id)
            if not isinstance(node, dict):
                return node_id
            return str(node.get("label") or node.get("name") or node_id)

        cluster_meta: dict[str, dict[str, str]] = {}
        for node_id, node in nodes.items():
            if not isinstance(node, dict):
                continue
            props = node.get("properties")
            if not isinstance(props, dict):
                continue
            if str(props.get("cluster_type") or "").strip() != "local_credential_reuse":
                continue
            cluster_meta[str(node_id)] = {
                "fingerprint": str(props.get("credential_fingerprint") or "").strip(),
                "credential_type": str(props.get("credential_type") or "").strip()
                or "-",
            }

        if not cluster_meta:
            return

        hosts_by_cluster: dict[str, set[str]] = {
            cluster_id: set() for cluster_id in cluster_meta
        }
        users_by_cluster: dict[str, set[str]] = {
            cluster_id: set() for cluster_id in cluster_meta
        }
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            relation = str(edge.get("relation") or "").strip().lower()
            src_id = str(edge.get("from") or "").strip()
            dst_id = str(edge.get("to") or "").strip()
            if (
                relation == "localcredreusesource"
                and dst_id in hosts_by_cluster
                and src_id
            ):
                hosts_by_cluster[dst_id].add(_node_label(src_id))
            elif (
                relation == "localcredtodomainreuse"
                and src_id in users_by_cluster
                and dst_id
            ):
                users_by_cluster[src_id].add(_node_label(dst_id))

        rows_with_key: list[tuple[tuple[int, int, str], dict[str, Any]]] = []
        for cluster_id, meta in cluster_meta.items():
            hosts = sorted(hosts_by_cluster.get(cluster_id, set()), key=str.lower)
            users = sorted(users_by_cluster.get(cluster_id, set()), key=str.lower)
            if not hosts and not users:
                continue
            hosts_preview = ", ".join(
                mark_sensitive(host, "hostname") for host in hosts[:3]
            )
            users_preview = ", ".join(
                mark_sensitive(user, "user") for user in users[:3]
            )
            if len(hosts) > 3:
                hosts_preview += f" (+{len(hosts) - 3} more)"
            if len(users) > 3:
                users_preview += f" (+{len(users) - 3} more)"
            rows_with_key.append(
                (
                    (-len(users), -len(hosts), str(meta.get("fingerprint") or "")),
                    {
                        "Credential Cluster": mark_sensitive(
                            str(meta.get("fingerprint") or "-"), "service"
                        ),
                        "Credential Type": str(meta.get("credential_type") or "-"),
                        "Source Hosts": len(hosts),
                        "Domain Users": len(users),
                        "Hosts": hosts_preview or "-",
                        "Users": users_preview or "-",
                    },
                )
            )

        if not rows_with_key:
            return
        rows = [row for _, row in sorted(rows_with_key, key=lambda item: item[0])]
        print_info_table(
            rows,
            [
                "Credential Cluster",
                "Credential Type",
                "Source Hosts",
                "Domain Users",
                "Hosts",
                "Users",
            ],
            title="Local Credential Reuse (Domain) Clusters",
        )

    if target_domain not in shell.domains:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_domain}' is not configured. Please add or select a valid domain."
        )
        return

    steps = compute_display_steps_for_domain(shell, target_domain, username=start_user)
    wanted_relations: set[str] | None = None
    if relation_filter:
        wanted_relations = {
            part.strip().lower()
            for part in str(relation_filter).split(",")
            if part.strip()
        }
        steps = [
            step
            for step in steps
            if str(step.get("action") or "").strip().lower() in wanted_relations
        ]
    if not steps:
        if start_user:
            print_warning(
                f"No attack steps recorded for user {mark_sensitive(start_user, 'user')}."
            )
        else:
            print_warning("No attack steps recorded for this domain.")
        return

    print_attack_steps_summary(
        target_domain,
        steps,
        max_display=max_display,
        start_user=start_user,
    )
    try:
        graph = load_attack_graph(shell, target_domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return
    if isinstance(graph, dict):
        _render_local_cred_domain_reuse_clusters(
            graph=graph,
            relation_terms=wanted_relations,
        )


def enumerate_user_aces(
    shell: BloodHoundShell,
    domain: str,
    username: str,
    password: str,
    group: str | None = None,
    cross_domain: bool | None = None,
) -> None:
    """Enumerate critical ACEs via BloodHound CE and offer exploitation.

    This function was extracted from the legacy ``enumerate_user_aces`` method
    in `adscan.py` to separate CLI orchestration from the shell class.
    """
    try:
        pwned_domains: list[str] = []
        if cross_domain:
            pwned_domains = [
                dom
                for dom, data in shell.domains_data.items()
                if data.get("auth", "").lower() == "pwned"
            ]

        used_high_value_filter = False
        output = ""

        if group:
            marked_group = mark_sensitive(group, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"Enumerating ACEs for group {marked_group} on high-value targets"
            )
            used_high_value_filter = True
            raw_aces = shell._get_graph_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=True,
                username=group,
                target_domain="all",
                relation="all",
            )
        elif cross_domain:
            marked_domain = mark_sensitive(domain, "domain")
            print_info(f"Enumerating ACEs for domain {marked_domain} on other domains")
            raw_aces = shell._get_graph_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=False,
                username="all",
                target_domain="all",
                relation="all",
            )
            if pwned_domains:
                blocked = {d.lower() for d in pwned_domains}
                raw_aces = [
                    a
                    for a in raw_aces
                    if str(a.get("targetDomain") or "").lower() not in blocked
                ]
        else:
            marked_username = mark_sensitive(username, "user")
            marked_domain = mark_sensitive(domain, "domain")
            print_info(
                f"Enumerating ACEs for user {marked_username} on high-value targets"
            )
            used_high_value_filter = True
            raw_aces = shell._get_graph_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=True,
                username=username,
                target_domain="all",
                relation="all",
            )

        aces = []
        for ace in raw_aces or []:
            source_domain_value = str(ace.get("sourceDomain") or domain)
            target_domain_value = str(ace.get("targetDomain") or domain)
            if source_domain_value.lower() == "n/a":
                source_domain_value = domain
            if target_domain_value.lower() == "n/a":
                target_domain_value = domain

            aces.append(
                {
                    "origen": ace.get("source", ""),
                    "tipoorigen": ace.get("sourceType", "Unknown"),
                    "dominio_origen": source_domain_value,
                    "destino": ace.get("target", ""),
                    "tipodestino": ace.get("targetType", "Unknown"),
                    "dominio_destino": target_domain_value,
                    "acl": ace.get("relation", ""),
                    "target_enabled": bool(ace.get("targetEnabled", True)),
                    "target_object_id": ace.get("targetObjectId", ""),
                }
            )

        # If no high-value ACEs were found and high-value filter was used, retry without it
        if not aces and not cross_domain and used_high_value_filter:
            print_error("No high-value ACEs found, retrying without --high-value...")
            used_high_value_filter = False
            if group:
                marked_group = mark_sensitive(group, "user")
                print_info(f"Enumerating ACEs for group {marked_group}")
            elif not cross_domain:
                marked_username = mark_sensitive(username, "user")
                print_info(f"Enumerating ACEs for user {marked_username}")
            raw_aces = shell._get_graph_service().get_critical_aces(  # type: ignore[attr-defined]
                source_domain=domain,
                high_value=False,
                username=(group or username or "all"),
                target_domain="all",
                relation="all",
            )
            aces = []
            for ace in raw_aces or []:
                source_domain_value = str(ace.get("sourceDomain") or domain)
                target_domain_value = str(ace.get("targetDomain") or domain)
                if source_domain_value.lower() == "n/a":
                    source_domain_value = domain
                if target_domain_value.lower() == "n/a":
                    target_domain_value = domain
                aces.append(
                    {
                        "origen": ace.get("source", ""),
                        "tipoorigen": ace.get("sourceType", "Unknown"),
                        "dominio_origen": source_domain_value,
                        "destino": ace.get("target", ""),
                        "tipodestino": ace.get("targetType", "Unknown"),
                        "dominio_destino": target_domain_value,
                        "acl": ace.get("relation", ""),
                        "target_enabled": bool(ace.get("targetEnabled", True)),
                        "target_object_id": ace.get("targetObjectId", ""),
                    }
                )

        if aces:
            aces_to_process = []
            retried_without_high_value = False

            while True:
                filtered_aces, skipped_aces = shell._filter_aces_by_adcs_requirement(
                    aces
                )

                if filtered_aces:
                    header_section = shell._extract_acl_header(output)
                    if header_section:
                        shell.console.print(header_section)  # type: ignore[attr-defined]
                    for ace_block in filtered_aces:
                        shell.console.print(shell._format_acl_block(ace_block))  # type: ignore[attr-defined]
                    aces_to_process = filtered_aces
                    break

                if (
                    not cross_domain
                    and used_high_value_filter
                    and not retried_without_high_value
                ):
                    if not aces:
                        print_error(
                            "No high-value ACEs found, retrying without --high-value..."
                        )
                    else:
                        print_info(
                            "No actionable high-value ACEs found, retrying without --high-value..."
                        )
                    retried_without_high_value = True
                    used_high_value_filter = False

                    raw_aces = shell._get_graph_service().get_critical_aces(  # type: ignore[attr-defined]
                        source_domain=domain,
                        high_value=False,
                        username=(group or username or "all"),
                        target_domain="all",
                        relation="all",
                    )
                    aces = []
                    for ace in raw_aces or []:
                        source_domain_value = str(ace.get("sourceDomain") or domain)
                        target_domain_value = str(ace.get("targetDomain") or domain)
                        if source_domain_value.lower() == "n/a":
                            source_domain_value = domain
                        if target_domain_value.lower() == "n/a":
                            target_domain_value = domain

                        aces.append(
                            {
                                "origen": ace.get("source", ""),
                                "tipoorigen": ace.get("sourceType", "Unknown"),
                                "dominio_origen": source_domain_value,
                                "destino": ace.get("target", ""),
                                "tipodestino": ace.get("targetType", "Unknown"),
                                "dominio_destino": target_domain_value,
                                "acl": ace.get("relation", ""),
                                "target_enabled": bool(ace.get("targetEnabled", True)),
                            }
                        )
                    continue

                if skipped_aces:
                    print_info(
                        "No actionable ACEs after filtering ADCS-dependent entries."
                    )
                else:
                    print_error("No ACEs found for this user")
                return

            # Process ACEs and offer exploitation options
            if aces_to_process:
                _process_aces_for_exploitation(
                    shell,
                    aces_to_process,
                    domain,
                    username,
                    password,
                    cross_domain=cross_domain,
                )
        else:
            print_warning("No critical ACEs found for enumeration.")

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"ACE enumeration failure details: type={type(exc).__name__} message={exc}"
        )
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error enumerating ACEs for domain {marked_domain}.")
        print_exception(show_locals=False, exception=exc)


def _process_aces_for_exploitation(
    shell: BloodHoundShell,
    aces_to_process: list[dict],
    domain: str,
    username: str,
    password: str,
    *,
    cross_domain: bool | None = None,
) -> None:
    """Process ACEs and offer exploitation options (legacy parity)."""
    exchange_ace = None
    for ace in aces_to_process:
        if (
            "genericall" in ace.get("acl", "").lower()
            and ace.get("destino", "").lower() == "exchange windows permissions"
        ):
            exchange_ace = ace
            print_warning(
                "There is an ACE with GenericAll on 'Exchange Windows Permissions'"
            )
            break

    for ace in aces_to_process:
        try:
            acl = ace.get("acl", "").lower()
            target_username = ace.get("destino", "")
            target_domain = ace.get("dominio_destino", "")
            display_name = mark_sensitive(target_username, "user")

            if cross_domain:
                username = ace.get("origen", username)
                password = shell.domains_data[domain]["credentials"][username]

            if "forcechangepassword" in acl:
                respuesta = Confirm.ask(
                    "Do you want to exploit the ForceChangePassword privilege on "
                    f"{display_name}?",
                    default=True,
                )
                if respuesta:
                    shell.exploit_force_change_password(
                        domain,
                        username,
                        password,
                        target_username,
                        target_domain,
                    )

            if "writespn" in acl:
                target_type = ace.get("tipodestino", "").lower()
                if target_type not in {"user", "computer"}:
                    print_warning(
                        f"WriteSPN exploitation is only supported for user/computer targets (got {target_type})."
                    )
                else:
                    respuesta = Confirm.ask(
                        "Do you want to exploit WriteSPN (Targeted Kerberoast) on "
                        f"{display_name}?",
                        default=True,
                    )
                    if respuesta:
                        shell.exploit_write_spn(
                            domain,
                            username,
                            password,
                            target_username,
                            target_domain,
                        )

            if "genericall" in acl or "genericwrite" in acl:
                if exchange_ace is not None and ace != exchange_ace:
                    continue

                target_type = ace.get("tipodestino", "").lower()
                if target_type in ("user", "computer"):
                    if not ace.get("target_enabled", True):
                        print_warning(f"Target user {display_name} is disabled.")
                        enable_respuesta = Confirm.ask(
                            "Do you want to try to enable the account first?",
                            default=True,
                        )
                        if enable_respuesta:
                            if not shell.enable_user(
                                domain, username, password, target_username
                            ):
                                print_error(
                                    f"Could not enable {display_name}. Skipping exploitation."
                                )
                                continue
                        else:
                            print_info(
                                f"Skipping exploitation for disabled user {display_name}."
                            )
                            continue

                    respuesta = Confirm.ask(
                        "Do you want to exploit the GenericAll/GenericWrite "
                        f"privilege on {display_name}?",
                        default=True,
                    )
                    if respuesta:
                        shell.exploit_generic_all_user(
                            domain,
                            username,
                            password,
                            target_username,
                            target_domain,
                        )
                elif target_type == "ou":
                    respuesta = Confirm.ask(
                        "Do you want to exploit the GenericAll/GenericWrite "
                        f"privilege on {display_name}?",
                        default=True,
                    )
                    if respuesta:
                        shell.exploit_generic_all_ou(
                            domain,
                            username,
                            password,
                            target_username,
                            target_domain,
                        )
                elif target_type == "group":
                    respuesta = Confirm.ask(
                        "Do you want to exploit the GenericAll/GenericWrite "
                        f"privilege on {display_name}?",
                        default=True,
                    )
                    if respuesta:
                        marked_username = mark_sensitive(username, "user")
                        changed_username = Prompt.ask(
                            "Enter the user you want to add: ",
                            default=marked_username,
                        )
                        shell.exploit_add_member(
                            domain,
                            username,
                            password,
                            target_username,
                            changed_username,
                            target_domain,
                        )

            if "addself" in acl:
                respuesta = Confirm.ask(
                    f"Do you want to exploit the AddSelf privilege on {display_name}?",
                    default=True,
                )
                if respuesta:
                    shell.exploit_add_member(
                        domain,
                        username,
                        password,
                        target_username,
                        username,
                        target_domain,
                    )

            if "addmember" in acl:
                respuesta = Confirm.ask(
                    f"Do you want to exploit the AddMember privilege on {display_name}?",
                    default=True,
                )
                if respuesta:
                    marked_username = mark_sensitive(username, "user")
                    changed_username = Prompt.ask(
                        "Enter the user you want to add: ",
                        default=marked_username,
                    )
                    shell.exploit_add_member(
                        domain,
                        username,
                        password,
                        target_username,
                        changed_username,
                        target_domain,
                    )

            if "readgmsapassword" in acl:
                respuesta = Confirm.ask(
                    "Do you want to exploit the ReadGMSAPassword privilege on "
                    f"{display_name}?",
                    default=True,
                )
                if respuesta:
                    shell.exploit_gmsa_account(
                        domain, username, password, target_username, target_domain
                    )

            if "readlapspassword" in acl:
                respuesta = Confirm.ask(
                    "Do you want to exploit the ReadLAPSPassword privilege on "
                    f"{display_name}?",
                    default=True,
                )
                if respuesta:
                    target_computer = f"{target_username.rstrip('$')}.{target_domain}"
                    shell.exploit_laps_password(
                        domain, username, password, target_computer, target_domain
                    )

            if "writedacl" in acl:
                target_type = ace.get("tipodestino", "").lower()
                if target_type in ("user", "group", "domain"):
                    marked_destino = mark_sensitive(
                        target_username, "domain" if target_type == "domain" else "user"
                    )
                    respuesta = Confirm.ask(
                        "Do you want to exploit the WriteDacl privilege on "
                        f"{marked_destino}?",
                        default=True,
                    )
                    if respuesta:
                        writedacl_ok = bool(
                            shell.exploit_write_dacl(
                                domain,
                                username,
                                password,
                                target_username,
                                target_domain,
                                target_type,
                            )
                        )
                        if writedacl_ok and target_type == "domain":
                            shell.ask_for_dcsync(domain, username, password)
                        elif writedacl_ok and target_type == "user":
                            shell.exploit_generic_all_user(
                                domain,
                                username,
                                password,
                                target_username,
                                target_domain,
                                prompt_for_user_privs_after=True,
                            )
                        elif writedacl_ok and target_type == "group":
                            marked_username = mark_sensitive(username, "user")
                            changed_username = Prompt.ask(
                                "Enter the user you want to add: ",
                                default=marked_username,
                            )
                            shell.exploit_add_member(
                                domain,
                                username,
                                password,
                                target_username,
                                changed_username,
                                target_domain,
                            )

            if "writeowner" in acl:
                target_type = ace.get("tipodestino", "").lower()
                if target_type in ("group", "user"):
                    respuesta = Confirm.ask(
                        "Do you want to exploit the WriteOwner privilege on "
                        f"{display_name}?",
                        default=True,
                    )
                    if respuesta:
                        writeowner_ok = bool(
                            shell.exploit_write_owner(
                                domain,
                                username,
                                password,
                                target_username,
                                target_domain,
                                target_type,
                            )
                        )
                        if writeowner_ok:
                            marked_destino = mark_sensitive(target_username, "user")
                            writedacl_respuesta = Confirm.ask(
                                "WriteOwner applied successfully. Do you want to "
                                f"try WriteDacl on {marked_destino} now?",
                                default=True,
                            )
                            if writedacl_respuesta:
                                shell.exploit_write_dacl(
                                    domain,
                                    username,
                                    password,
                                    target_username,
                                    target_domain,
                                    target_type,
                                )

            if "dcsync" in acl:
                marked_destino = mark_sensitive(target_username, "domain")
                respuesta = Confirm.ask(
                    "Do you want to exploit the DCSync privilege on domain "
                    f"{marked_destino}?",
                    default=True,
                )
                if respuesta:
                    shell.dcsync(domain, username, password)

        except Exception as exc:
            telemetry.capture_exception(exc)
            continue


def parse_acls(output: str) -> list[dict]:
    """Parse the output of bloodhound-cli acl and return a list of ACEs.

    This function was extracted from the legacy ``parse_acls`` method
    in `adscan.py` to separate BloodHound parsing logic from the shell class.

    Args:
        output: The raw output string from bloodhound-cli acl command

    Returns:
        List of ACE dictionaries with keys: origen, tipoorigen, dominio_origen,
        destino, tipodestino, dominio_destino, acl, target_enabled
    """
    aces = []
    current_ace = {}

    # Split the output into lines
    lines = output.strip().split("\n")

    for line in lines:
        line = line.strip()

        # Skip empty lines and headers
        if not line or line.startswith("ACEs for user:") or line.startswith("==="):
            continue

        # If we find a separator line, save the current ACE and start a new one
        if line.startswith("---"):
            if current_ace:
                # Default target_enabled to True if not found
                if "target_enabled" not in current_ace:
                    current_ace["target_enabled"] = True

                # Check that we have all the required fields before adding
                required_fields = [
                    "origen",
                    "tipoorigen",
                    "dominio_origen",
                    "destino",
                    "tipodestino",
                    "dominio_destino",
                    "acl",
                ]
                if all(field in current_ace for field in required_fields):
                    aces.append(current_ace)
            current_ace = {}
            continue

        # Process data line
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            # Map the keys
            key_mapping = {
                "source": "origen",
                "source type": "tipoorigen",
                "source domain": "dominio_origen",
                "target": "destino",
                "target type": "tipodestino",
                "target domain": "dominio_destino",
                "relation": "acl",
            }

            if key in key_mapping:
                current_ace[key_mapping[key]] = value
            elif key == "target enabled":  # Handle the new key
                # The value will be 'False' when the target is disabled.
                current_ace["target_enabled"] = value.lower() == "true"

    # Add the last ACE if it exists and the file doesn't end with a separator
    if current_ace:
        if "target_enabled" not in current_ace:
            current_ace["target_enabled"] = True
        required_fields = [
            "origen",
            "tipoorigen",
            "dominio_origen",
            "destino",
            "tipodestino",
            "dominio_destino",
            "acl",
        ]
        if all(field in current_ace for field in required_fields):
            aces.append(current_ace)

    return aces


# ============================================================================
# User Enumeration Functions
# ============================================================================


def run_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Create BloodHound user lists for the specified domain.

    ADscan writes the enabled-user inventory plus the product-owned control
    exposure inventories used by the rest of the platform.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    run_all_users(shell, target_domain)
    run_control_exposure_identities(shell, target_domain)
    run_direct_domain_control_identities(shell, target_domain)
    run_domain_compromise_enablers(shell, target_domain)
    run_high_impact_privileges(shell, target_domain)
    if hasattr(shell, "update_report_field"):
        try:
            from adscan_internal.services.identity_choke_point_service import (
                load_or_build_identity_choke_point_snapshot,
            )

            snapshot = load_or_build_identity_choke_point_snapshot(shell, target_domain)
            choke_points = (
                snapshot.get("choke_points") if isinstance(snapshot, dict) else None
            )
            shell.update_report_field(
                target_domain,
                "identity_choke_points",
                choke_points,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)


def run_all_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a BloodHound user list for the specified domain and save it to a file.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    from adscan_internal.cli.intelligence import run_native_identity_inventory

    run_native_identity_inventory(shell, target_domain)
    return

    try:
        users = shell._get_graph_service().get_users(domain=target_domain)
        shell._write_user_list_file(target_domain, "enabled_users.txt", users)
        shell._postprocess_user_list_file(
            target_domain,
            "enabled_users.txt",
            source="bloodhound_enabled_users",
        )
        build_identity_risk_snapshot(shell, target_domain)
        build_identity_choke_point_snapshot(shell, target_domain)
        emit_event(
            "coverage",
            phase="domain_analysis",
            phase_label="Domain Analysis",
            category="identity_inventory",
            domain=target_domain,
            metric_type="enabled_users",
            count=len(users),
            message=f"Enabled identity inventory updated: {len(users)} active users discovered.",
        )
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound user query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def run_control_exposure_identities(shell: BloodHoundShell, target_domain: str) -> None:
    """Persist the ADscan control-exposure identity inventory for one domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate admin users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        snapshot = load_or_build_identity_risk_snapshot(shell, target_domain)
        users = (
            snapshot.get("control_exposure_identities")
            if isinstance(snapshot, dict)
            else []
        )
        if not isinstance(users, list):
            users = []
        shell._write_user_list_file(
            target_domain, CONTROL_EXPOSURE_IDENTITIES_FILENAME, users
        )
        shell._postprocess_user_list_file(
            target_domain,
            CONTROL_EXPOSURE_IDENTITIES_FILENAME,
            source="adscan_identity_control_exposure_identities",
        )
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound control exposure inventory query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def run_direct_domain_control_identities(
    shell: BloodHoundShell, target_domain: str
) -> None:
    """Persist the direct-domain-control identity inventory for one domain."""
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        snapshot = load_or_build_identity_risk_snapshot(shell, target_domain)
        users = (
            snapshot.get("direct_domain_control_identities")
            if isinstance(snapshot, dict)
            else []
        )
        if not isinstance(users, list):
            users = []
        shell._write_user_list_file(
            target_domain, DIRECT_DOMAIN_CONTROL_IDENTITIES_FILENAME, users
        )
        shell._postprocess_user_list_file(
            target_domain,
            DIRECT_DOMAIN_CONTROL_IDENTITIES_FILENAME,
            source="adscan_identity_direct_domain_control",
            trigger_followups=False,
        )
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound direct domain control inventory query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def run_domain_compromise_enablers(shell: BloodHoundShell, target_domain: str) -> None:
    """Persist the domain-compromise-enabler identity inventory for one domain."""
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        snapshot = load_or_build_identity_risk_snapshot(shell, target_domain)
        users = (
            snapshot.get("domain_compromise_enablers")
            if isinstance(snapshot, dict)
            else []
        )
        if not isinstance(users, list):
            users = []
        shell._write_user_list_file(
            target_domain, DOMAIN_COMPROMISE_ENABLERS_FILENAME, users
        )
        shell._postprocess_user_list_file(
            target_domain,
            DOMAIN_COMPROMISE_ENABLERS_FILENAME,
            source="adscan_identity_domain_compromise_enablers",
            trigger_followups=False,
        )
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound domain compromise enabler inventory query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def run_high_impact_privileges(shell: BloodHoundShell, target_domain: str) -> None:
    """Persist the high-impact privilege inventory for one domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    try:
        snapshot = load_or_build_identity_risk_snapshot(shell, target_domain)
        users = (
            snapshot.get("high_impact_privileges") if isinstance(snapshot, dict) else []
        )
        if not isinstance(users, list):
            users = []
        shell._write_user_list_file(
            target_domain, HIGH_IMPACT_PRIVILEGES_FILENAME, users
        )
        shell._postprocess_user_list_file(
            target_domain,
            HIGH_IMPACT_PRIVILEGES_FILENAME,
            source="adscan_identity_high_impact_privileges",
            trigger_followups=False,
        )
        return
    except Exception as e:
        telemetry.capture_exception(e)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"BloodHound high-impact privilege inventory query failed for {marked_target_domain}. Ensure data is ingested in BloodHound CE."
        )
        print_exception(show_locals=False, exception=e)
        return


def ask_for_users(shell: BloodHoundShell, target_domain: str) -> None:
    """Ask user if they want to enumerate BloodHound users for the domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate users for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    if shell.auto:
        run_users(shell, target_domain)
    else:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        if Confirm.ask(
            f"Do you want to enumerate BloodHound users for the domain {marked_target_domain}?",
            default=True,
        ):
            run_users(shell, target_domain)


# ============================================================================
# Password Policy Functions
# ============================================================================


def _segment_password_policy_users(
    shell: BloodHoundShell,
    *,
    domain: str,
    users: list[str],
) -> dict[str, object]:
    """Split risky users into direct-control, control-exposed, and standard segments."""
    ordered_users: list[str] = []
    normalized_to_display: dict[str, str] = {}
    for user in users:
        display = str(user or "").strip()
        normalized = normalize_samaccountname(display)
        if not display or not normalized or normalized in normalized_to_display:
            continue
        normalized_to_display[normalized] = display
        ordered_users.append(display)

    flags = classify_users_tier0_high_value(
        shell,
        domain=domain,
        usernames=ordered_users,
    )

    direct_domain_control_users: list[str] = []
    control_exposure_users: list[str] = []
    standard_users: list[str] = []
    for user in ordered_users:
        normalized = normalize_samaccountname(user)
        risk = flags.get(normalized, UserRiskFlags())
        if risk.is_tier0:
            direct_domain_control_users.append(user)
        elif risk.is_high_value:
            control_exposure_users.append(user)
        else:
            standard_users.append(user)

    return {
        "all_users": ordered_users or None,
        "direct_domain_control_users": direct_domain_control_users or None,
        "control_exposure_users": control_exposure_users or None,
        "standard_users": standard_users or None,
        "total_count": len(ordered_users),
        "direct_domain_control_count": len(direct_domain_control_users),
        "control_exposure_count": len(control_exposure_users),
        "standard_count": len(standard_users),
    }


def _persist_password_policy_segment_artifacts(
    shell: BloodHoundShell,
    *,
    domain: str,
    base_filename: str,
    segmented_users: dict[str, object],
) -> dict[str, str]:
    """Write segmented user lists to workspace artifacts."""
    base_name = os.path.splitext(base_filename)[0]
    artifact_paths: dict[str, str] = {}
    mapping = {
        "direct_domain_control_users": f"{base_name}_direct_domain_control.txt",
        "control_exposure_users": f"{base_name}_control_exposure.txt",
        "standard_users": f"{base_name}_standard.txt",
    }
    for segment_key, filename in mapping.items():
        users = segmented_users.get(segment_key)
        if isinstance(users, list) and users:
            artifact_paths[segment_key] = shell._write_user_list_file(
                domain,
                filename,
                users,
            )
    return artifact_paths


def _render_identity_hygiene_segmentation_summary(
    *,
    domain: str,
    title: str,
    posture_label: str,
    total_label: str,
    no_findings_posture: str,
    direct_posture: str,
    control_posture: str,
    standard_posture: str,
    segmented_users: dict[str, object],
    artifact_paths: dict[str, str],
    context_lines: list[str] | None = None,
) -> None:
    """Render a consistent tiered identity-risk summary for hygiene checks.

    Args:
        domain: Domain name being assessed.
        title: Panel/table title for this check.
        posture_label: Label for the summary posture line.
        total_label: Label for the total affected identity count.
        no_findings_posture: Posture text when no matching identities exist.
        direct_posture: Posture text when direct domain-control identities exist.
        control_posture: Posture text when control-exposed identities exist.
        standard_posture: Posture text when only standard identities exist.
        segmented_users: Output from `_segment_password_policy_users`.
        artifact_paths: Segment artifact paths returned by `_persist_password_policy_segment_artifacts`.
        context_lines: Optional extra summary lines, such as stale-user thresholds.
    """
    direct_users = segmented_users.get("direct_domain_control_users") or []
    control_users = segmented_users.get("control_exposure_users") or []
    standard_users = segmented_users.get("standard_users") or []
    total_count = int(segmented_users.get("total_count") or 0)
    direct_count = int(segmented_users.get("direct_domain_control_count") or 0)
    control_count = int(segmented_users.get("control_exposure_count") or 0)
    standard_count = int(segmented_users.get("standard_count") or 0)

    posture = (
        direct_posture
        if direct_count
        else control_posture
        if control_count
        else standard_posture
        if total_count
        else no_findings_posture
    )
    border_style, glyph, posture_style = _severity_palette(
        critical_hit=bool(direct_count),
        high_hit=bool(control_count),
        has_findings=bool(total_count),
    )
    artifact_count = sum(1 for path in artifact_paths.values() if path)

    # Header: number first, label second (TUI design § 4 hierarchy
    # recipe). Color reserved for the posture severity slot. Hygiene
    # metrics live in a compact two-column grid rather than seven flat
    # lines so the panel reads as one block, not a list.
    header = Text()
    header.append("Domain  ", style="dim")
    header.append(
        f"{mark_sensitive(domain, 'domain')}\n", style=f"bold {ADSCAN_PRIMARY}"
    )
    for ctx in context_lines or []:
        header.append(f"{ctx}\n", style="dim")
    header.append(f"{posture_label}  ", style="dim")
    header.append(f"{posture}\n", style=posture_style)
    header.append(f"{total_label}  ", style="dim")
    header.append(f"{total_count}", style="bold")
    header.append("    Direct  ", style="dim")
    header.append(
        f"{direct_count}",
        style=f"bold {COLOR_CRIMSON}" if direct_count else COLOR_MUTED,
    )
    header.append("    Exposed  ", style="dim")
    header.append(
        f"{control_count}",
        style=f"bold {COLOR_AMBER}" if control_count else COLOR_MUTED,
    )
    header.append("    Standard  ", style="dim")
    header.append(
        f"{standard_count}",
        style=f"bold {COLOR_STEEL}" if standard_count else COLOR_MUTED,
    )
    header.append("    Artifacts  ", style="dim")
    header.append(f"{artifact_count}", style="bold")

    if total_count == 0:
        _get_console().print(
            Panel(
                header,
                title=Text(f" {glyph}  {title} ", style="bold"),
                title_align="left",
                border_style=border_style,
                box=ROUNDED,
                padding=(1, 2),
            )
        )
        return

    table = Table(
        title="Breakdown by Priority",
        title_style="bold",
        show_header=True,
        header_style="dim bold",
        box=SIMPLE,
        pad_edge=False,
        padding=(0, 1),
    )
    table.add_column("Priority", no_wrap=True)
    table.add_column("Identities", justify="right", no_wrap=True)
    table.add_column("Why it matters", max_width=72)
    table.add_column("Artifact", style="dim", max_width=34)

    # The highest non-empty tier gets a star prefix + accent color so the
    # eye lands on it instantly. Lower tiers carry their own muted color
    # and stay readable. Glyph pairing (!!, !, ?) keeps the hierarchy
    # legible under NO_COLOR.
    top_key = (
        "direct"
        if direct_count
        else "control"
        if control_count
        else "standard"
        if standard_count
        else None
    )
    table.add_row(
        _ranked_priority_cell(
            rank="P0",
            label="Direct control",
            glyph="!!",
            color=COLOR_CRIMSON,
            is_top=top_key == "direct",
        ),
        _count_cell(direct_count, hot=True, severity=COLOR_CRIMSON),
        Text(
            "Identities on the direct domain-control boundary. Treat as immediate remediation."
            if direct_count
            else "No direct domain-control identities found.",
            style="default" if direct_count else COLOR_MUTED,
        ),
        Text(
            _format_segment_artifact(artifact_paths, "direct_domain_control_users"),
            style="dim",
        ),
    )
    table.add_row(
        _ranked_priority_cell(
            rank="P1",
            label="Control exposed",
            glyph="!",
            color=COLOR_AMBER,
            is_top=top_key == "control",
        ),
        _count_cell(control_count, hot=True, severity=COLOR_AMBER),
        Text(
            "Not direct-control accounts; their graph exposure can still enable escalation."
            if control_count
            else "No additional control-exposed identities found.",
            style="default" if control_count else COLOR_MUTED,
        ),
        Text(
            _format_segment_artifact(artifact_paths, "control_exposure_users"),
            style="dim",
        ),
    )
    table.add_row(
        _ranked_priority_cell(
            rank="P2",
            label="Standard",
            glyph="?",
            color=COLOR_STEEL,
            is_top=top_key == "standard",
        ),
        _count_cell(standard_count, hot=False, severity=COLOR_STEEL),
        Text(
            "Hygiene findings without known control exposure; still reduce them to shrink attack surface."
            if standard_count
            else "No standard identities found.",
            style="default" if standard_count else COLOR_MUTED,
        ),
        Text(
            _format_segment_artifact(artifact_paths, "standard_users"),
            style="dim",
        ),
    )

    # Action footer per panel (TUI § 3 progressive disclosure). Tells
    # the pentester the very next move that matches the worst tier
    # surfaced, so the panel ends with intent, not data.
    next_action = Text()
    next_action.append("Next:  ", style="dim")
    if direct_count:
        next_action.append(
            "rotate or disable the P0 identities immediately; they short-circuit Tier 0.",
            style="default",
        )
    elif control_count:
        next_action.append(
            "review P1 identities for excess privilege; remove standing access where possible.",
            style="default",
        )
    elif standard_count:
        next_action.append(
            "trim P2 hygiene findings as part of normal AD maintenance to shrink attack surface.",
            style="default",
        )
    else:
        next_action.append(
            "no remediation needed for this check.",
            style=COLOR_MUTED,
        )

    samples_renderable = _build_identity_hygiene_samples_renderable(
        direct_users=direct_users,
        control_users=control_users,
        standard_users=standard_users,
        direct_count=direct_count,
        control_count=control_count,
        standard_count=standard_count,
    )

    body: list[Any] = [header, Text(""), table]
    if samples_renderable is not None:
        body.extend([Text(""), samples_renderable])
    body.extend([Text(""), next_action])

    _get_console().print(
        Panel(
            Group(*body),
            title=Text(f" {glyph}  {title} ", style="bold"),
            title_align="left",
            border_style=border_style,
            box=ROUNDED,
            padding=(1, 2),
        )
    )


def _format_segment_artifact(artifact_paths: dict[str, str], segment_key: str) -> str:
    """Return a compact artifact name for summary tables."""
    artifact_path = artifact_paths.get(segment_key)
    if not artifact_path:
        return "N/A"
    return mark_sensitive(os.path.basename(artifact_path), "path")


def _render_identity_hygiene_samples(
    *,
    direct_users: object,
    control_users: object,
    standard_users: object,
    direct_count: int,
    control_count: int,
    standard_count: int,
) -> None:
    """Render small identity samples using one consistent naming scheme.

    Preserved for backward compatibility; the segmentation panel now
    composes samples inline via ``_build_identity_hygiene_samples_renderable``
    so they live inside the same ``Panel(Group(...))`` as the breakdown
    table. Direct callers (if any) still get the legacy stacked panels.
    """
    samples = [
        ("P0 direct control sample", direct_users, direct_count, "!!"),
        ("P1 control-exposed sample", control_users, control_count, "!"),
        ("P2 standard sample", standard_users, standard_count, "?"),
    ]
    for title, users, count, glyph in samples:
        if not isinstance(users, list) or not users:
            continue
        print_info_list(
            [mark_sensitive(user, "user") for user in users[:5]],
            title=f"{glyph}  {title}  ({count} total)",
            icon="-",
        )


def _build_identity_hygiene_samples_renderable(
    *,
    direct_users: object,
    control_users: object,
    standard_users: object,
    direct_count: int,
    control_count: int,
    standard_count: int,
) -> Group | None:
    """Return a single Rich Group with up to three labeled sample blocks.

    Used by the segmentation panel so samples live inside the parent
    Panel (no nested cards, single spatial unit). Returns ``None`` when
    every segment is empty so the caller can skip the spacer row.
    """
    samples = [
        ("P0 direct control", direct_users, direct_count, "!!", COLOR_CRIMSON),
        ("P1 control exposed", control_users, control_count, "!", COLOR_AMBER),
        ("P2 standard", standard_users, standard_count, "?", COLOR_STEEL),
    ]
    blocks: list[Text] = []
    for title, users, count, glyph, color in samples:
        if not isinstance(users, list) or not users:
            continue
        line = Text()
        line.append(f"{glyph}  ", style=f"bold {color}")
        line.append(f"{title}  ", style=f"bold {color}")
        line.append(f"({count} total)\n", style="dim")
        line.append(
            "    " + ", ".join(mark_sensitive(user, "user") for user in users[:5]),
            style="default",
        )
        if len(users) > 5:
            line.append(f"  (+{len(users) - 5} more)", style="dim")
        blocks.append(line)
    if not blocks:
        return None
    rendered: list[Text] = []
    for idx, block in enumerate(blocks):
        if idx > 0:
            rendered.append(Text(""))
        rendered.append(block)
    return Group(*rendered)


def _render_password_policy_user_summary(
    *,
    domain: str,
    title: str,
    segmented_users: dict[str, object],
    artifact_paths: dict[str, str],
) -> None:
    """Render one premium summary for password policy hygiene findings."""
    _render_identity_hygiene_segmentation_summary(
        domain=domain,
        title=title,
        posture_label="Risk posture",
        total_label="Affected users",
        no_findings_posture="No matching users identified",
        direct_posture="Critical: direct domain-control identities affected",
        control_posture="High: control-exposed identities affected",
        standard_posture="Moderate: limited to standard identities",
        segmented_users=segmented_users,
        artifact_paths=artifact_paths,
    )


def _build_segmented_user_details(
    raw_records: list[dict[str, object]],
    segmented_users: dict[str, object],
) -> dict[str, list[dict[str, object]]]:
    """Attach per-user metadata to direct-control/control-exposure/standard segments."""
    records_by_normalized: dict[str, dict[str, object]] = {}
    for record in raw_records:
        if not isinstance(record, dict):
            continue
        normalized = normalize_samaccountname(str(record.get("samaccountname") or ""))
        if normalized:
            records_by_normalized[normalized] = record

    details: dict[str, list[dict[str, object]]] = {}
    for segment_key in (
        "direct_domain_control_users",
        "control_exposure_users",
        "standard_users",
    ):
        users = segmented_users.get(segment_key)
        if not isinstance(users, list):
            continue
        rows: list[dict[str, object]] = []
        for user in users:
            normalized = normalize_samaccountname(str(user or ""))
            row = dict(records_by_normalized.get(normalized) or {})
            row["samaccountname"] = user
            rows.append(row)
        details[segment_key] = rows
    return details


def _render_stale_enabled_user_summary(
    *,
    domain: str,
    title: str,
    segmented_users: dict[str, object],
    artifact_paths: dict[str, str],
    stale_days: int,
) -> None:
    """Render one premium summary for enabled-but-stale users."""
    _render_identity_hygiene_segmentation_summary(
        domain=domain,
        title=title,
        posture_label="Hygiene posture",
        total_label="Stale enabled users",
        no_findings_posture="No stale enabled users identified",
        direct_posture="Critical: stale direct domain-control identities remain enabled",
        control_posture="High: stale control-exposed identities remain enabled",
        standard_posture="Moderate: stale exposure limited to standard identities",
        segmented_users=segmented_users,
        artifact_paths=artifact_paths,
        context_lines=[f"Threshold: {stale_days} days without observed logon activity"],
    )


def _load_workspace_user_list(
    shell: BloodHoundShell,
    *,
    domain: str,
    filename: str,
) -> list[str]:
    """Load one workspace user list file preserving display values."""
    workspace_cwd = shell._get_workspace_cwd()
    file_path = domain_subpath(workspace_cwd, shell.domains_dir, domain, filename)
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            return [line.strip() for line in handle if line.strip()]
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[user-lists] failed to read {file_path}: {exc}")
        return []


def _calculate_control_exposure_sprawl(
    *,
    enabled_users: list[str],
    control_exposed_users: list[str],
) -> dict[str, object]:
    """Calculate control-exposure sprawl metrics from two user inventories."""
    enabled_unique = sorted(
        {str(user).strip() for user in enabled_users if str(user).strip()}
    )
    enabled_keys = {normalize_samaccountname(user) for user in enabled_unique}
    enabled_keys.discard(None)  # type: ignore[arg-type]

    privileged_unique = sorted(
        {str(user).strip() for user in control_exposed_users if str(user).strip()}
    )
    privileged_in_enabled: list[str] = []
    for user in privileged_unique:
        normalized = normalize_samaccountname(user)
        if normalized and normalized in enabled_keys:
            privileged_in_enabled.append(user)

    enabled_count = len(enabled_unique)
    privileged_count = len(privileged_in_enabled)
    ratio = (privileged_count / enabled_count) if enabled_count else 0.0

    if privileged_count >= 20 or ratio >= 0.20:
        posture = "Critical: Control-exposure identity sprawl"
        exceeds_threshold = True
    elif privileged_count >= 10 or ratio >= 0.10:
        posture = "High: Control-exposed identity concentration is elevated"
        exceeds_threshold = True
    elif privileged_count >= 5 and ratio >= 0.05:
        posture = "Moderate: Control-exposed identity footprint should be reduced"
        exceeds_threshold = True
    else:
        posture = "Controlled: No material control-exposure sprawl detected"
        exceeds_threshold = False

    return {
        "enabled_user_count": enabled_count,
        "control_exposure_count": privileged_count,
        "control_exposure_ratio": round(ratio, 4),
        "control_exposure_percentage": round(ratio * 100, 2),
        "control_exposure_users": privileged_in_enabled or None,
        "exceeds_threshold": exceeds_threshold,
        "posture": posture,
    }


def _render_control_exposure_sprawl_summary(
    *,
    domain: str,
    metrics: dict[str, object],
) -> None:
    """Render a premium summary for control-exposure identity sprawl."""
    enabled_count = int(metrics.get("enabled_user_count") or 0)
    privileged_count = int(metrics.get("control_exposure_count") or 0)
    percentage = float(metrics.get("control_exposure_percentage") or 0.0)
    posture = str(metrics.get("posture") or "Unknown")
    privileged_users = metrics.get("control_exposure_users") or []

    critical = percentage >= 20 or privileged_count >= 20
    high = bool(metrics.get("exceeds_threshold")) and not critical
    border_style, glyph, posture_style = _severity_palette(
        critical_hit=critical,
        high_hit=high,
        has_findings=privileged_count > 0,
    )

    # Headline: ratio reads as the metric that matters most, so it goes
    # first and largest. Number-first / label-second per TUI § 4. The
    # baseline figures sit on the same row in muted text so the eye does
    # not weight them equally with the ratio.
    headline = Text()
    headline.append(f"{percentage:.2f}%  ", style=f"bold {posture_style.split()[-1]}")
    headline.append("of enabled users carry control exposure\n", style="default")
    headline.append("Domain  ", style="dim")
    headline.append(
        f"{mark_sensitive(domain, 'domain')}", style=f"bold {ADSCAN_PRIMARY}"
    )
    headline.append("    Enabled  ", style="dim")
    headline.append(f"{enabled_count}", style="bold")
    headline.append("    Exposed  ", style="dim")
    headline.append(
        f"{privileged_count}",
        style=f"bold {COLOR_CRIMSON}"
        if critical
        else (f"bold {COLOR_AMBER}" if high else "bold"),
    )
    headline.append("\n", style="default")
    headline.append("Assessment  ", style="dim")
    headline.append(posture, style=posture_style)

    table = Table(
        title="Concentration Detail",
        title_style="bold",
        show_header=True,
        header_style="dim bold",
        box=SIMPLE,
        pad_edge=False,
        padding=(0, 1),
    )
    table.add_column("Metric")
    table.add_column("Value", justify="right", no_wrap=True)
    table.add_column("Interpretation", max_width=72)
    table.add_row(
        Text("Enabled users", style="default"),
        Text(str(enabled_count), style="bold"),
        Text(
            "Active identity baseline used for hygiene ratio calculations.",
            style=COLOR_MUTED,
        ),
    )
    table.add_row(
        Text("Control-exposed identities", style="default"),
        _count_cell(
            privileged_count,
            hot=critical or high,
            severity=COLOR_CRIMSON if critical else COLOR_AMBER,
        ),
        Text(
            "Users sourced from control_exposure_identities.txt.",
            style=COLOR_MUTED,
        ),
    )
    table.add_row(
        Text("Control exposure ratio", style="default"),
        Text(
            f"{percentage:.2f}%",
            style=(
                f"bold {COLOR_CRIMSON}"
                if critical
                else f"bold {COLOR_AMBER}"
                if high
                else "bold"
            ),
        ),
        Text(
            (
                "Elevated control-exposure concentration increases standing access and widens the blast radius of credential compromise."
                if bool(metrics.get("exceeds_threshold"))
                else "Control-exposure concentration appears comparatively contained."
            ),
            style="default",
        ),
    )

    body: list[Any] = [headline, Text(""), table]
    if isinstance(privileged_users, list) and privileged_users:
        sample_line = Text()
        sample_line.append("Sample  ", style="dim")
        sample_line.append(f"({privileged_count} total)\n", style="dim")
        sample_line.append(
            "    "
            + ", ".join(mark_sensitive(user, "user") for user in privileged_users[:8]),
            style="default",
        )
        if len(privileged_users) > 8:
            sample_line.append(f"  (+{len(privileged_users) - 8} more)", style="dim")
        body.extend([Text(""), sample_line])

    # Action footer: pentester reads the panel from top to bottom; the
    # final line tells them what to do, not what they just saw.
    next_action = Text()
    next_action.append("Next:  ", style="dim")
    if critical:
        next_action.append(
            "trim the control-exposed pool urgently; review tier-0 nesting and remove standing membership where possible.",
            style="default",
        )
    elif high:
        next_action.append(
            "audit the control-exposed identities for legitimate need; convert standing access to just-in-time where feasible.",
            style="default",
        )
    elif privileged_count > 0:
        next_action.append(
            "monitor concentration over time; budget hygiene work proportional to growth.",
            style=COLOR_MUTED,
        )
    else:
        next_action.append(
            "no remediation needed; keep the concentration ratio under observation.",
            style=COLOR_MUTED,
        )
    body.extend([Text(""), next_action])

    _get_console().print(
        Panel(
            Group(*body),
            title=Text(f" {glyph}  Control-Exposure Identity Sprawl ", style="bold"),
            title_align="left",
            border_style=border_style,
            box=ROUNDED,
            padding=(1, 2),
        )
    )


def run_tier0_highvalue_sprawl(shell: BloodHoundShell, domain: str) -> None:
    """Assess control-exposure identity concentration using current inventories."""
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Assessing control-exposure identity concentration on domain {marked_domain}"
    )
    try:
        enabled_users = _load_workspace_user_list(
            shell,
            domain=domain,
            filename="enabled_users.txt",
        )
        if not enabled_users:
            print_info_debug(
                "[identity-sprawl] enabled_users.txt missing or empty; querying BloodHound."
            )
            enabled_users = shell._get_graph_service().get_users(domain=domain)
            shell._write_user_list_file(domain, "enabled_users.txt", enabled_users)

        control_exposed_users = _load_workspace_user_list(
            shell,
            domain=domain,
            filename=CONTROL_EXPOSURE_IDENTITIES_FILENAME,
        )
        if not control_exposed_users:
            print_info_debug(
                "[identity-sprawl] control_exposure_identities.txt missing or empty; rebuilding identity risk snapshot."
            )
            snapshot = load_or_build_identity_risk_snapshot(shell, domain)
            control_exposed_users = (
                snapshot.get("control_exposure_identities")
                if isinstance(snapshot, dict)
                else []
            )
            if not isinstance(control_exposed_users, list):
                control_exposed_users = []
            shell._write_user_list_file(
                domain,
                CONTROL_EXPOSURE_IDENTITIES_FILENAME,
                control_exposed_users,
            )

        metrics = _calculate_control_exposure_sprawl(
            enabled_users=enabled_users,
            control_exposed_users=control_exposed_users,
        )
        execute_tier0_highvalue_sprawl(
            shell,
            domain=domain,
            metrics=metrics,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to assess control-exposure identity concentration.")
        print_exception(show_locals=False, exception=exc)


def run_pwdneverexpires(shell: BloodHoundShell, domain: str) -> None:
    """Create a list of users with password never expires in the specified domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to query
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Searching for users with password never expiring on domain {marked_domain}"
    )
    try:
        users = shell._get_graph_service().get_users(
            domain=domain, filter_type="pwd_never_expires"
        )
        shell._write_user_list_file(domain, "pwdneverexpires.txt", users)
        execute_passnotreq(shell, None, domain, "pwdneverexpires.txt", users=users)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query graph for password-never-expires users.")
        print_exception(show_locals=False, exception=exc)


def run_passnotreq(shell: BloodHoundShell, domain: str) -> None:
    """Create a list of users with password not required in the specified domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to query
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Searching for users with password not required on domain {marked_domain}"
    )
    try:
        users = shell._get_graph_service().get_users(
            domain=domain, filter_type="pwd_not_required"
        )
        shell._write_user_list_file(domain, "passnotreq.txt", users)
        execute_passnotreq(shell, None, domain, "passnotreq.txt", users=users)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query graph for password-not-required users.")
        print_exception(show_locals=False, exception=exc)


def run_stale_enabled_users(
    shell: BloodHoundShell,
    domain: str,
    *,
    stale_days: int = 180,
) -> None:
    """Create a list of enabled users with stale logon activity in the domain."""
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Searching for enabled stale users on domain {marked_domain} "
        f"(threshold: {stale_days} days)"
    )
    try:
        records = shell._get_graph_service().get_stale_enabled_users(
            domain=domain,
            stale_days=stale_days,
        )
        users = [
            str(record.get("samaccountname") or "").strip()
            for record in records
            if isinstance(record, dict)
            and str(record.get("samaccountname") or "").strip()
        ]
        shell._write_user_list_file(domain, "stale_enabled_users.txt", users)
        execute_stale_enabled_users(
            shell,
            None,
            domain,
            "stale_enabled_users.txt",
            users=users,
            records=records,
            stale_days=stale_days,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query graph for stale enabled users.")
        print_exception(show_locals=False, exception=exc)


def execute_passnotreq(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    file: str,
    users: list[str] | None = None,
) -> None:
    """Execute the BloodHound command to find users with specific password policies.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when users is provided)
        domain: Domain name
        file: Output filename
        users: List of users (if None, will read from file)
    """
    try:
        if users is None:
            print_info_verbose(f"Executing BloodHound command for {file}: {command}")
            completed_process = shell.run_command(command, timeout=300)
            errors = completed_process.stderr
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error creating the user list via BloodHound for domain {marked_domain}:"
                )
                if errors:
                    print_error(errors.strip())
                return

            workspace_cwd = shell._get_workspace_cwd()
            users_file = domain_subpath(workspace_cwd, shell.domains_dir, domain, file)
            try:
                with open(users_file, "r", encoding="utf-8") as f:
                    users = [line.strip() for line in f if line.strip()]
            except Exception as e:
                telemetry.capture_exception(e)
                print_error("Error reading the users file.")
                print_exception(show_locals=False, exception=e)
                return

        # Define the key to update based on the file
        if file == "passnotreq.txt":
            key = "password_not_req"
            title = "Password Not Required Risk Segmentation"
        elif file == "pwdneverexpires.txt":
            key = "password_never_expires"
            title = "Password Never Expires Risk Segmentation"
        else:
            key = file
            title = "Users"

        segmented_users = _segment_password_policy_users(
            shell,
            domain=domain,
            users=users or [],
        )
        artifact_paths = _persist_password_policy_segment_artifacts(
            shell,
            domain=domain,
            base_filename=file,
            segmented_users=segmented_users,
        )
        value = segmented_users if users else False
        shell.update_report_field(domain, key, value)
        _render_password_policy_user_summary(
            domain=domain,
            title=title,
            segmented_users=segmented_users,
            artifact_paths=artifact_paths,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Error creating the user list via BloodHound for domain {marked_domain}: {str(e)}"
        )
        print_exception(show_locals=False, exception=e)


def execute_stale_enabled_users(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    file: str,
    *,
    users: list[str] | None = None,
    records: list[dict[str, object]] | None = None,
    stale_days: int = 180,
) -> None:
    """Execute stale-enabled-user rendering and persist structured evidence."""
    try:
        if users is None:
            print_info_verbose(f"Executing BloodHound command for {file}: {command}")
            completed_process = shell.run_command(command, timeout=300)
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error creating the stale-enabled-user list via BloodHound for domain {marked_domain}:"
                )
                if completed_process.stderr:
                    print_error(completed_process.stderr.strip())
                return
            workspace_cwd = shell._get_workspace_cwd()
            users_file = domain_subpath(workspace_cwd, shell.domains_dir, domain, file)
            with open(users_file, "r", encoding="utf-8") as handle:
                users = [line.strip() for line in handle if line.strip()]

        segmented_users = _segment_password_policy_users(
            shell,
            domain=domain,
            users=users or [],
        )
        segmented_details = _build_segmented_user_details(
            records or [], segmented_users
        )
        artifact_paths = _persist_password_policy_segment_artifacts(
            shell,
            domain=domain,
            base_filename=file,
            segmented_users=segmented_users,
        )
        details = {
            **segmented_users,
            "stale_days_threshold": stale_days,
            "segmented_details": segmented_details,
        }
        value = segmented_users if users else False
        shell.update_report_field(domain, "stale_enabled_users", value)
        try:
            from adscan_core.reporting.technical_report import record_technical_finding

            record_technical_finding(
                shell,
                domain,
                key="stale_enabled_users",
                value=bool(users),
                details=details,
                evidence=[
                    {
                        "type": "artifact",
                        "summary": "BloodHound stale enabled users list",
                        "artifact_path": domain_relpath(
                            shell.domains_dir, domain, file
                        ),
                    }
                ],
            )
        except Exception as exc:  # pragma: no cover
            if not handle_optional_report_service_exception(
                exc,
                action="Technical finding sync",
                debug_printer=print_info_debug,
                prefix="[stale-users]",
            ):
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[stale-users] Failed to persist technical finding: {exc}"
                )

        _render_stale_enabled_user_summary(
            domain=domain,
            title="Stale Enabled Users Risk Segmentation",
            segmented_users=segmented_users,
            artifact_paths=artifact_paths,
            stale_days=stale_days,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Error creating the stale-enabled-user list via BloodHound for domain {marked_domain}: {str(e)}"
        )
        print_exception(show_locals=False, exception=e)


def execute_tier0_highvalue_sprawl(
    shell: BloodHoundShell,
    *,
    domain: str,
    metrics: dict[str, object],
) -> None:
    """Persist and render control-exposure identity concentration metrics."""
    try:
        affected_users = metrics.get("control_exposure_users")
        if not isinstance(affected_users, list):
            affected_users = []

        artifact_path = shell._write_user_list_file(
            domain,
            "control_exposure_sprawl.txt",
            affected_users,
        )
        value = {
            **metrics,
            "artifact_path": domain_relpath(
                shell.domains_dir,
                domain,
                "control_exposure_sprawl.txt",
            ),
        }
        shell.update_report_field(domain, "control_exposure_sprawl", value)
        try:
            from adscan_core.reporting.technical_report import record_technical_finding

            record_technical_finding(
                shell,
                domain,
                key="control_exposure_sprawl",
                value=bool(metrics.get("exceeds_threshold")),
                details=value,
                evidence=[
                    {
                        "type": "artifact",
                        "summary": "Enabled user inventory used for sprawl baseline",
                        "artifact_path": domain_relpath(
                            shell.domains_dir,
                            domain,
                            "enabled_users.txt",
                        ),
                    },
                    {
                        "type": "artifact",
                        "summary": "Control-exposure identity inventory",
                        "artifact_path": domain_relpath(
                            shell.domains_dir,
                            domain,
                            CONTROL_EXPOSURE_IDENTITIES_FILENAME,
                        ),
                    },
                    {
                        "type": "artifact",
                        "summary": "Control-exposed identities within enabled-user baseline",
                        "artifact_path": domain_relpath(
                            shell.domains_dir,
                            domain,
                            "control_exposure_sprawl.txt",
                        ),
                    },
                ],
            )
        except Exception as exc:  # pragma: no cover
            if not handle_optional_report_service_exception(
                exc,
                action="Technical finding sync",
                debug_printer=print_info_debug,
                prefix="[identity-sprawl]",
            ):
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[identity-sprawl] Failed to persist technical finding: {exc}"
                )

        print_info_debug(
            f"[identity-sprawl] Wrote intersection artifact to {mark_sensitive(artifact_path, 'path')}"
        )
        _render_control_exposure_sprawl_summary(
            domain=domain,
            metrics=metrics,
        )
    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Error assessing control-exposure identity concentration for domain {marked_domain}: {str(e)}"
        )
        print_exception(show_locals=False, exception=e)


# ============================================================================
# DC Access Functions
# ============================================================================


def run_dc_access(shell: BloodHoundShell, domain: str) -> None:
    """Check non-admin users access privileges on DCs on domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to query
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(
        f"Checking non admin users access privs on DCs on domain {marked_domain}"
    )
    try:
        paths = shell._get_graph_service().get_users_with_dc_access(domain)
        execute_dc_access(shell, None, domain, paths=paths)
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Failed to query graph for DC access paths.")
        print_exception(show_locals=False, exception=exc)


def execute_dc_access(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    paths: list[dict] | None = None,
) -> None:
    """Execute the BloodHound command and process the output for DC access.

    For each target (destino) and each relation (acl):
    - If more than 10 accounts possess the relation, print the count.
    - Otherwise, print the account names.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when paths is provided)
        domain: Domain name
        paths: List of access path dictionaries (if None, will execute command)
    """
    try:
        if paths is None:
            print_info_verbose(f"Executing BloodHound DC access check: {command}")
            completed_process = shell.run_command(command, timeout=300)
            stdout = completed_process.stdout
            stderr = completed_process.stderr

            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error executing BloodHound DC access command for domain {marked_domain} (Return Code: {completed_process.returncode}):"
                )
                if stderr:
                    print_error(f"Stderr: {stderr.strip()}")
                elif stdout:
                    print_error(f"Stdout: {stdout.strip()}")
                return

            if stderr:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"Warnings/errors from BloodHound DC access command for domain {marked_domain}: {stderr.strip()}"
                )

            paths = []
            if stdout:
                paths = parse_acls(stdout)
            else:
                marked_domain = mark_sensitive(domain, "domain")
                print_warning(
                    f"No stdout received from BloodHound DC access check for domain {marked_domain}."
                )

        aces = []
        for entry in paths or []:
            if "acl" in entry and "destino" in entry:
                aces.append(entry)
                continue
            # BloodHoundService returns dicts like: {source, target, path}
            src = entry.get("source") or ""
            tgt = entry.get("target") or ""
            relation = entry.get("relation") or ""
            path_text = entry.get("path") or ""
            if not relation and path_text:
                match = re.search(r"\\(([^)]+)\\)\\s*$", path_text)
                if match:
                    relation = match.group(1)

            if src and tgt:
                aces.append(
                    {
                        "origen": src,
                        "tipoorigen": "User",
                        "dominio_origen": domain,
                        "destino": tgt,
                        "tipodestino": "Computer",
                        "dominio_destino": domain,
                        "acl": relation or "Unknown",
                        "target_enabled": True,
                    }
                )

        # Group the ACEs by target (destino) and relation (acl)
        groups = {}
        for ace in aces:
            target = ace.get("destino")
            relation = ace.get("acl")
            account = ace.get("origen")
            if target and relation and account:
                key = (target, relation)
                groups.setdefault(key, []).append(account)

        # Display the results:
        # If there are more than 10 accounts, display the count.
        # Otherwise, list the account names.
        for (target, relation), accounts in groups.items():
            if len(accounts) > 10:
                print_warning(
                    f"Target: {target}, Relation: {relation} -> Accounts count: {len(accounts)}"
                )
            else:
                accounts_list = ", ".join(accounts)
                print_warning(
                    f"Target: {target}, Relation: {relation} -> Accounts: {accounts_list}"
                )

    except Exception as e:
        telemetry.capture_exception(e)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Exception during execution of bloodhound command for domain {marked_domain}: {str(e)}"
        )


# ============================================================================
# KRBTGT Functions
# ============================================================================


def _parse_bloodhound_epoch(value: object) -> datetime | None:
    """Convert BloodHound epoch-like values to an aware UTC datetime."""
    if value in (None, "", 0, "0"):
        return None
    try:
        parsed = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    try:
        return datetime.fromtimestamp(parsed, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _resolve_krbtgt_last_change(
    records: list[dict[str, object]],
) -> tuple[datetime | None, dict[str, object] | None]:
    """Return the best ``krbtgt`` password-last-change record from BloodHound data."""
    for record in records:
        if not isinstance(record, dict):
            continue
        username = str(record.get("samaccountname") or "").strip().lower()
        if username != "krbtgt":
            continue
        last_change = _parse_bloodhound_epoch(record.get("pwdlastset"))
        if last_change is not None:
            return last_change, record
    return None, None


def run_krbtgt(shell: BloodHoundShell, domain: str) -> None:
    """Check the ``krbtgt`` password age using the active BloodHound service.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        domain: Domain name to check
    """
    marked_domain = mark_sensitive(domain, "domain")
    print_info(f"Checking krbtgt's last password change on domain {marked_domain}")
    try:
        records = shell._get_graph_service().get_password_last_change(
            domain=domain,
            user="krbtgt",
            enabled_only=False,
        )
        execute_krbtgt(shell, None, domain, records=records)
    except Exception as e:
        telemetry.capture_exception(e)
        print_error(
            f"Failed to query BloodHound for krbtgt password age in domain {marked_domain}"
        )
        print_exception(show_locals=False, exception=e)


def execute_krbtgt(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    *,
    records: list[dict[str, object]] | None = None,
) -> None:
    """Persist ``krbtgt`` password age from BloodHound query data.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Legacy compatibility argument, unused when records are provided
        domain: Domain name
        records: Structured BloodHound password-last-change records
    """
    try:
        if records is None:
            print_info_debug(
                "[krbtgt] Legacy execute path invoked without structured records; querying BloodHound service."
            )
            records = shell._get_graph_service().get_password_last_change(
                domain=domain,
                user="krbtgt",
                enabled_only=False,
            )
    except Exception as e:
        telemetry.capture_exception(e)
        print_error(f"Error retrieving krbtgt password age data: {e}")
        return

    last_change, record = _resolve_krbtgt_last_change(records or [])
    if last_change is None:
        marked_domain = mark_sensitive(domain, "domain")
        print_error(
            f"Unable to resolve krbtgt password last change from BloodHound data in domain {marked_domain}"
        )
        return

    now = datetime.now(timezone.utc)
    diff = now - last_change
    flag = diff.days >= 365
    shell.update_report_field(domain, "krbtgt_pass", flag)

    marked_domain = mark_sensitive(domain, "domain")
    date_str = last_change.strftime("%Y-%m-%d %H:%M:%S %Z")
    posture = "stale" if flag else "recent"
    print_success(
        f"krbtgt password was last changed on {date_str} in domain {marked_domain}"
    )
    print_info_debug(
        "[krbtgt] password age assessment: "
        f"domain={marked_domain} "
        f"days_since_change={diff.days} "
        f"posture={posture} "
        f"record={record}"
    )


# ============================================================================
# Computer Enumeration Functions
# ============================================================================


def ask_for_computers(shell: BloodHoundShell, target_domain: str) -> None:
    """Ask user if they want to enumerate BloodHound computers for the domain.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if shell.auto:
        run_computers(shell, target_domain)
    else:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        answer = Confirm.ask(
            f"Do you want to enumerate BloodHound computers for the domain {marked_target_domain}?"
        )
        if answer:
            run_computers(shell, target_domain)


def run_computers(shell: BloodHoundShell, target_domain: str) -> None:
    """Create computer lists for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    run_computers_all(shell, target_domain)
    persist_bloodhound_membership_snapshot(shell, target_domain)
    if shell.type == "ctf":
        return
    if shell.auto:
        run_computers_with_laps(shell, target_domain)
        run_computers_without_laps(shell, target_domain)
    else:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        if Confirm.ask(
            f"Do you want to enumerate computers with/without LAPS for the domain {marked_target_domain}?"
        ):
            run_computers_with_laps(shell, target_domain)
            run_computers_without_laps(shell, target_domain)
        marked_target_domain = mark_sensitive(target_domain, "domain")


def run_computers_all(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a list of enabled computers for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return

    from adscan_internal.cli.intelligence import run_native_host_inventory

    run_native_host_inventory(shell, target_domain)
    return

    try:
        computers = shell._get_graph_service().get_computers(domain=target_domain)
        emit_event(
            "coverage",
            phase="domain_analysis",
            phase_label="Domain Analysis",
            category="host_inventory",
            domain=target_domain,
            metric_type="enabled_hosts",
            count=len(computers),
            message=f"Enabled host inventory updated: {len(computers)} active computers discovered.",
        )
        shell._process_computers_list(target_domain, "enabled_computers.txt", computers)
    except Exception as exc:
        telemetry.capture_exception(exc)
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Error enumerating computers via BloodHound for domain {marked_target_domain}."
        )
        print_exception(show_locals=False, exception=exc)


def run_computers_with_laps(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a list of enabled computers with LAPS for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info(
        f"Searching for enabled computers with LAPS on domain {marked_target_domain}"
    )
    try:
        from adscan_internal.cli.intelligence import _host_inventory_name
        from adscan_internal.services.attack_graph_service import load_attack_graph
        from adscan_internal.services.graph_queries import get_laps_computers

        graph = load_attack_graph(shell, target_domain)
        computers = [
            _host_inventory_name(computer, target_domain)
            for computer in get_laps_computers(graph, target_domain)
        ]
        computers = [computer for computer in computers if computer]
        execute_laps(
            shell,
            None,
            target_domain,
            "enabled_computers_with_laps.txt",
            computers=computers,
        )
        return

        computers = shell._get_graph_service().get_computers(
            domain=target_domain, laps_filter=True
        )
        execute_laps(
            shell,
            None,
            target_domain,
            "enabled_computers_with_laps.txt",
            computers=computers,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error enumerating LAPS-enabled computers.")
        print_exception(show_locals=False, exception=exc)


def run_computers_without_laps(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a list of enabled computers without LAPS for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computers for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info(
        f"Searching for enabled computers without LAPS on domain {marked_target_domain}"
    )
    try:
        from adscan_internal.cli.intelligence import _host_inventory_name
        from adscan_internal.services.attack_graph_service import load_attack_graph
        from adscan_internal.services.graph_queries import get_non_laps_computers

        graph = load_attack_graph(shell, target_domain)
        computers = [
            _host_inventory_name(computer, target_domain)
            for computer in get_non_laps_computers(graph, target_domain)
        ]
        computers = [computer for computer in computers if computer]
        execute_laps(
            shell,
            None,
            target_domain,
            "enabled_computers_without_laps.txt",
            computers=computers,
        )
        return

        computers = shell._get_graph_service().get_computers(
            domain=target_domain, laps_filter=False
        )
        execute_laps(
            shell,
            None,
            target_domain,
            "enabled_computers_without_laps.txt",
            computers=computers,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error enumerating non-LAPS computers.")
        print_exception(show_locals=False, exception=exc)


def execute_laps(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    comp_file: str,
    computers: list[str] | None = None,
) -> None:
    """Execute the BloodHound LAPS computer enumeration command and process the output.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when computers is provided)
        domain: Domain name
        comp_file: Output filename
        computers: List of computers (if None, will execute command)
    """
    try:
        if computers is None:
            print_info_verbose("Executing BloodHound LAPS computer enumeration")
            completed_process = shell.run_command(command, timeout=300)
            errors = completed_process.stderr
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error enumerating computers in domain with/without LAPS {marked_domain}."
                )
                if errors:
                    print_error(errors)
                return
        else:
            errors = ""

        if computers is not None:
            shell._write_domain_list_file(domain, comp_file, computers)

        marked_domain = mark_sensitive(domain, "domain")
        print_success_verbose(
            f"LAPS computer list ({comp_file}) successfully generated for domain {marked_domain}."
        )
        # Path to the computers file within the domain directory
        workspace_cwd = shell._get_workspace_cwd()
        computers_file = domain_subpath(
            workspace_cwd, shell.domains_dir, domain, comp_file
        )
        try:
            # Read the computers file (ignoring empty lines)
            with open(computers_file, "r", encoding="utf-8") as file:
                computers = [line.strip() for line in file if line.strip()]
            count = len(computers)

            # Classify computers into DCs and non-DCs
            dc_list = []
            non_dc_list = []
            for computer in computers:
                if shell.is_computer_dc(domain, computer):
                    dc_list.append(computer)
                else:
                    non_dc_list.append(computer)
            count_dc = len(dc_list)
            count_non_dc = len(non_dc_list)

            def _write_host_list(path: str, hosts: list[str]) -> None:
                with open(path, "w", encoding="utf-8") as file_handle:
                    for host in hosts:
                        file_handle.write(host + "\n")

            def _render_laps_inventory_panel(
                *,
                laps_state_label: str,
                border_style: str,
                dc_file: str | None,
                non_dc_file: str | None,
            ) -> None:
                marked_domain_local = mark_sensitive(domain, "domain")
                marked_main_file = mark_sensitive(
                    os.path.join(shell.domains_dir, domain, comp_file), "path"
                )
                marked_dc_file = mark_sensitive(dc_file, "path") if dc_file else "N/A"
                marked_non_dc_file = (
                    mark_sensitive(non_dc_file, "path") if non_dc_file else "N/A"
                )
                dc_ratio = (count_dc / count * 100.0) if count > 0 else 0.0
                non_dc_ratio = (count_non_dc / count * 100.0) if count > 0 else 0.0
                print_panel(
                    "\n".join(
                        [
                            f"Domain: {marked_domain_local}",
                            f"LAPS state: {laps_state_label}",
                            f"Total enabled computers: {count}",
                            f"Domain Controllers: {count_dc} ({dc_ratio:.1f}%)",
                            f"Non-DC computers: {count_non_dc} ({non_dc_ratio:.1f}%)",
                            "",
                            "Artifacts",
                            f"- Full inventory: {marked_main_file}",
                            f"- DC subset: {marked_dc_file}",
                            f"- Non-DC subset: {marked_non_dc_file}",
                        ]
                    ),
                    title="LAPS Inventory Summary",
                    border_style=border_style,
                    fit=True,
                )

                dc_preview = [mark_sensitive(host, "hostname") for host in dc_list[:5]]
                non_dc_preview = [
                    mark_sensitive(host, "hostname") for host in non_dc_list[:5]
                ]
                if dc_preview:
                    print_info_list(
                        dc_preview,
                        title=f"DC sample ({len(dc_list)} total)",
                        icon="🖥️",
                    )
                if non_dc_preview:
                    print_info_list(
                        non_dc_preview,
                        title=f"Non-DC sample ({len(non_dc_list)} total)",
                        icon="💻",
                    )

            # Depending on the file (with or without LAPS), print and generate the corresponding files
            if comp_file == "enabled_computers_with_laps.txt":
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"LAPS-enabled inventory generated for domain {marked_domain} ({count} hosts)."
                )
                emit_event(
                    "coverage",
                    phase="domain_analysis",
                    phase_label="Domain Analysis",
                    category="laps_inventory",
                    domain=domain,
                    metric_type="laps_enabled_hosts",
                    count=count,
                    message=f"Managed local administrator protection confirmed on {count} hosts.",
                )
                dc_file = None
                non_dc_file = None
                if dc_list:
                    dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_with_laps_dcs.txt",
                    )
                    _write_host_list(dc_file, dc_list)
                if non_dc_list:
                    non_dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_with_laps_non_dcs.txt",
                    )
                    _write_host_list(non_dc_file, non_dc_list)
                _render_laps_inventory_panel(
                    laps_state_label="Enabled",
                    border_style="green",
                    dc_file=dc_file,
                    non_dc_file=non_dc_file,
                )

            elif comp_file == "enabled_computers_without_laps.txt":
                marked_domain = mark_sensitive(domain, "domain")
                print_success(
                    f"LAPS-missing inventory generated for domain {marked_domain} ({count} hosts)."
                )
                emit_event(
                    "coverage",
                    phase="domain_analysis",
                    phase_label="Domain Analysis",
                    category="laps_inventory",
                    domain=domain,
                    metric_type="laps_missing_hosts",
                    count=count,
                    message=f"Managed local administrator protection is missing on {count} hosts.",
                )
                dc_file = None
                non_dc_file = None
                if dc_list:
                    dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_without_laps_dcs.txt",
                    )
                    _write_host_list(dc_file, dc_list)
                if non_dc_list:
                    non_dc_file = os.path.join(
                        shell.domains_dir,
                        domain,
                        "enabled_computers_without_laps_non_dcs.txt",
                    )
                    _write_host_list(non_dc_file, non_dc_list)
                _render_laps_inventory_panel(
                    laps_state_label="Not enabled",
                    border_style="yellow",
                    dc_file=dc_file,
                    non_dc_file=non_dc_file,
                )

                value = {
                    "all_computers": computers if computers else None,
                    "dcs": dc_list if dc_list else None,
                    "non_dcs": non_dc_list if non_dc_list else None,
                }

                shell.update_report_field(domain, "laps", value)

        except Exception as e:
            telemetry.capture_exception(e)
            print_error("Error reading the computers file.")
            print_exception(show_locals=False, exception=e)

    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing graph query.")
        print_exception(show_locals=False, exception=e)


# ============================================================================
# Session Enumeration Functions
# ============================================================================


def run_sessions(shell: BloodHoundShell, target_domain: str) -> None:
    """Create a list of computers with Domain Admin sessions for the specified domain using BloodHound.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        target_domain: Domain name to enumerate computer sessions for
    """
    if target_domain not in shell.domains:
        marked_target_domain = mark_sensitive(target_domain, "domain")
        print_error(
            f"Domain '{marked_target_domain}' is not configured. Please add or select a valid domain."
        )
        return
    marked_target_domain = mark_sensitive(target_domain, "domain")
    print_info_verbose(
        f"Searching for Domain Admin sessions on non DC computers on domain {marked_target_domain}"
    )
    try:
        sessions = shell._get_graph_service().get_sessions(
            domain=target_domain, domain_admin_only=True
        )
        execute_sessions(
            shell,
            None,
            target_domain,
            "computers_da_sessions.txt",
            sessions=sessions,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_error("Error querying graph for sessions.")
        print_exception(show_locals=False, exception=exc)


def execute_sessions(
    shell: BloodHoundShell,
    command: str | None,
    domain: str,
    comp_file: str,
    sessions: list[dict] | None = None,
) -> None:
    """Execute the BloodHound session enumeration command and process the output.

    Args:
        shell: Shell instance implementing BloodHoundShell protocol
        command: Command string (legacy, not used when sessions is provided)
        domain: Domain name
        comp_file: Output filename
        sessions: List of session dictionaries (if None, will execute command)
    """
    try:
        if sessions is None:
            print_info("Searching for Domain Admin sessions on non DC computers")
            completed_process = shell.run_command(command, timeout=300)
            errors = completed_process.stderr
            if completed_process.returncode != 0:
                marked_domain = mark_sensitive(domain, "domain")
                print_error(
                    f"Error enumerating computers with DA sessions in domain {marked_domain}."
                )
                if errors:
                    print_error(errors)
                return
            sessions = []

        da_computers = []
        for entry in sessions or []:
            computer = str(entry.get("computer") or "").strip()
            if computer:
                da_computers.append(computer)

        da_computers = list(dict.fromkeys([c.lower() for c in da_computers]))

        if not da_computers:
            shell._write_domain_list_file(domain, comp_file, ["No sessions found."])
            shell.update_report_field(domain, "da_sessions", None)
            return

        shell._write_domain_list_file(domain, comp_file, da_computers)
        shell.update_report_field(domain, "da_sessions", da_computers)
        shell._display_items(da_computers, "Computers with Domain Admin sessions")
    except Exception as e:
        telemetry.capture_exception(e)
        print_error("Error executing graph sessions query.")
        print_exception(show_locals=False, exception=e)


# ============================================================================
# Collector Functions
# ============================================================================
