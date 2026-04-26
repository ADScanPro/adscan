"""ADscan identity choke-point discovery.

This service persists structural choke points discovered from membership
relationships, reusing the central choke-point classifier shared with runtime
attack-step creation.
"""

from __future__ import annotations

from collections import defaultdict
import os
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.choke_point_classifier import (
    classify_control_transition,
)
from adscan_internal.services.identity_risk_service import (
    classify_group_control_level,
    load_or_build_identity_risk_snapshot,
)
from adscan_internal.services.membership_snapshot import load_membership_snapshot
from adscan_internal.workspaces import domain_subpath, read_json_file, write_json_file

IDENTITY_CHOKE_POINT_SNAPSHOT_FILENAME = "identity_choke_points.json"


def _workspace_cwd(shell: object) -> str:
    getter = getattr(shell, "_get_workspace_cwd", None)
    if callable(getter):
        try:
            return str(getter())
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
    return str(getattr(shell, "current_workspace_dir", os.getcwd()) or os.getcwd())


def _snapshot_path(shell: object, domain: str) -> str:
    return domain_subpath(
        _workspace_cwd(shell),
        str(getattr(shell, "domains_dir", "domains") or "domains"),
        domain,
        IDENTITY_CHOKE_POINT_SNAPSHOT_FILENAME,
    )


def _canonical_membership_label(domain: str, value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "@" in raw:
        left, _, right = raw.partition("@")
        if left and right:
            return f"{left.strip().upper()}@{right.strip().upper()}"
    return f"{raw.upper()}@{str(domain or '').strip().upper()}"


def _normalize_username(value: str) -> str:
    name = str(value or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.strip().lower()


def build_identity_choke_point_snapshot(shell: object, domain: str) -> dict[str, Any]:
    """Build and persist choke points for one domain."""
    snapshot = load_membership_snapshot(shell, domain)
    identity_snapshot = load_or_build_identity_risk_snapshot(shell, domain)
    if not isinstance(snapshot, dict):
        result = {"domain": domain, "version": 1, "choke_points": []}
        write_json_file(_snapshot_path(shell, domain), result)
        return result

    user_to_groups = snapshot.get("user_to_groups")
    group_to_parents = snapshot.get("group_to_parents")
    label_to_sid = snapshot.get("label_to_sid")
    if not isinstance(user_to_groups, dict) or not isinstance(group_to_parents, dict):
        result = {"domain": domain, "version": 1, "choke_points": []}
        write_json_file(_snapshot_path(shell, domain), result)
        return result
    if not isinstance(label_to_sid, dict):
        label_to_sid = {}

    risk_users = identity_snapshot.get("users") if isinstance(identity_snapshot, dict) else {}
    if not isinstance(risk_users, dict):
        risk_users = {}

    all_group_labels: set[str] = set()
    for groups in user_to_groups.values():
        if isinstance(groups, list):
            all_group_labels.update(
                _canonical_membership_label(domain, value) for value in groups
            )
    for child, parents in group_to_parents.items():
        all_group_labels.add(_canonical_membership_label(domain, child))
        if isinstance(parents, list):
            all_group_labels.update(
                _canonical_membership_label(domain, value) for value in parents
            )

    group_meta: dict[str, dict[str, Any]] = {}
    for label in all_group_labels:
        group_name = label.split("@", 1)[0]
        group_meta[label] = classify_group_control_level(
            sid=str(label_to_sid.get(label) or ""),
            name=group_name,
        )

    users_by_group: dict[str, set[str]] = defaultdict(set)
    stack_cache: dict[str, set[str]] = {}

    def _expand_group(group_label: str) -> set[str]:
        if group_label in stack_cache:
            return stack_cache[group_label]
        seen: set[str] = set()
        stack = [group_label]
        while stack:
            current = stack.pop()
            if not current or current in seen:
                continue
            seen.add(current)
            for parent in group_to_parents.get(current, []):
                canonical = _canonical_membership_label(domain, parent)
                if canonical and canonical not in seen:
                    stack.append(canonical)
        stack_cache[group_label] = seen
        return seen

    for user_label, direct_groups in user_to_groups.items():
        username = _normalize_username(user_label)
        if not username:
            continue
        resolved: set[str] = set()
        for direct_group in direct_groups if isinstance(direct_groups, list) else []:
            canonical = _canonical_membership_label(domain, direct_group)
            if not canonical:
                continue
            resolved.update(_expand_group(canonical))
        for group_label in resolved:
            users_by_group[group_label].add(username)

    choke_points: list[dict[str, Any]] = []

    for user_label, direct_groups in user_to_groups.items():
        username = _normalize_username(user_label)
        if not username:
            continue
        source_record = risk_users.get(username)
        source_control_level = (
            str(source_record.get("control_level") or "standard")
            if isinstance(source_record, dict)
            else "standard"
        )
        for direct_group in direct_groups if isinstance(direct_groups, list) else []:
            target_label = _canonical_membership_label(domain, direct_group)
            target_meta = group_meta.get(target_label, {})
            record = classify_control_transition(
                source_label=username,
                source_kind="user",
                source_control_level=source_control_level,
                target_label=target_label.split("@", 1)[0],
                target_kind="group",
                target_control_level=str(
                    target_meta.get("control_level") or "standard"
                ),
                transition_type="membership_assignment",
                blast_radius=1,
                affected_user_count=1,
                source_semantics={
                    "control_level": source_control_level,
                    "equivalence_class": str(
                        source_record.get("equivalence_class") or "standard"
                    )
                    if isinstance(source_record, dict)
                    else "standard",
                },
                target_semantics=target_meta,
                reason=(
                    f"{username} gains membership exposure to "
                    f"{target_label.split('@', 1)[0]}"
                ),
            )
            if isinstance(record, dict):
                choke_points.append(record)

    for child_group, parent_groups in group_to_parents.items():
        source_label = _canonical_membership_label(domain, child_group)
        source_meta = group_meta.get(source_label, {})
        source_control_level = str(source_meta.get("control_level") or "standard")
        for parent in parent_groups if isinstance(parent_groups, list) else []:
            target_label = _canonical_membership_label(domain, parent)
            target_meta = group_meta.get(target_label, {})
            affected_users = users_by_group.get(source_label, set())
            record = classify_control_transition(
                source_label=source_label.split("@", 1)[0],
                source_kind="group",
                source_control_level=source_control_level,
                target_label=target_label.split("@", 1)[0],
                target_kind="group",
                target_control_level=str(
                    target_meta.get("control_level") or "standard"
                ),
                transition_type="membership_assignment",
                blast_radius=len(affected_users),
                affected_user_count=len(affected_users),
                source_semantics=source_meta,
                target_semantics=target_meta,
                reason=(
                    f"{source_label.split('@', 1)[0]} exposes its members to "
                    f"{target_label.split('@', 1)[0]}"
                ),
            )
            if isinstance(record, dict):
                samples = sorted(affected_users, key=str.lower)[:10]
                record["affected_user_samples"] = samples
                choke_points.append(record)

    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in choke_points:
        key = (
            str(record.get("source_kind") or ""),
            str(record.get("source_label") or "").lower(),
            str(record.get("target_label") or "").lower(),
        )
        previous = deduped.get(key)
        if previous is None or int(record.get("blast_radius") or 0) > int(
            previous.get("blast_radius") or 0
        ):
            deduped[key] = record

    ordered = sorted(
        deduped.values(),
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                str(item.get("severity") or "low"), 9
            ),
            -int(item.get("blast_radius") or 0),
            str(item.get("title") or "").lower(),
        ),
    )
    result = {"domain": domain, "version": 1, "choke_points": ordered}
    write_json_file(_snapshot_path(shell, domain), result)
    print_info_debug(
        "[identity-choke-points] snapshot built: "
        f"domain={mark_sensitive(domain, 'domain')} count={len(ordered)}"
    )
    return result


def load_identity_choke_point_snapshot(shell: object, domain: str) -> dict[str, Any] | None:
    """Load the persisted choke-point snapshot when available."""
    path = _snapshot_path(shell, domain)
    if not os.path.exists(path):
        return None
    data = read_json_file(path)
    return data if isinstance(data, dict) else None


def load_or_build_identity_choke_point_snapshot(
    shell: object,
    domain: str,
) -> dict[str, Any]:
    """Return the persisted choke-point snapshot, building it when missing."""
    loaded = load_identity_choke_point_snapshot(shell, domain)
    if isinstance(loaded, dict):
        return loaded
    return build_identity_choke_point_snapshot(shell, domain)
