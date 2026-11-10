"""Deferred cleanup helpers for environment-altering attack-path steps."""

from __future__ import annotations

from adscan_internal.services.ledger_guard import ledger_or_warn

import secrets
from datetime import UTC, datetime
from typing import Any

from adscan_internal import print_info, telemetry
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.attack_graph_service import update_edge_status_by_labels
from adscan_internal.services.membership_snapshot import (
    remove_runtime_user_group_membership,
)
from adscan_core.rich_output import print_exception

_CLEANUP_SCOPE_ATTR = "_attack_path_cleanup_scopes"

def _utc_now_iso() -> str:
    """Return one UTC timestamp in ISO format."""
    return datetime.now(UTC).isoformat()


def _get_cleanup_scopes(shell: Any) -> list[dict[str, Any]]:
    """Return the mutable cleanup scope stack stored on the shell."""
    scopes = getattr(shell, _CLEANUP_SCOPE_ATTR, None)
    if not isinstance(scopes, list):
        scopes = []
        setattr(shell, _CLEANUP_SCOPE_ATTR, scopes)
    return scopes


def has_active_cleanup_scope(shell: Any) -> bool:
    """Return whether one deferred cleanup scope is currently active."""
    return bool(_get_cleanup_scopes(shell))


def begin_cleanup_scope(shell: Any, *, label: str, domain: str) -> str:
    """Push one cleanup scope and return its opaque identifier."""
    scope_id = f"cleanup-{secrets.token_hex(6)}"
    _get_cleanup_scopes(shell).append(
        {
            "id": scope_id,
            "label": str(label or "").strip(),
            "domain": str(domain or "").strip(),
            "actions": [],
            "started_at": _utc_now_iso(),
        }
    )
    return scope_id


def discard_cleanup_scope(shell: Any, *, scope_id: str) -> None:
    """Remove one cleanup scope without executing any action."""
    scopes = _get_cleanup_scopes(shell)
    setattr(
        shell,
        _CLEANUP_SCOPE_ATTR,
        [scope for scope in scopes if str(scope.get("id") or "") != scope_id],
    )


def _find_cleanup_scope(shell: Any, scope_id: str) -> dict[str, Any] | None:
    """Return one cleanup scope by id."""
    for scope in _get_cleanup_scopes(shell):
        if str(scope.get("id") or "") == scope_id:
            return scope
    return None


def _mark_group_membership_cleanup_panel(
    *,
    target_group: str,
    added_user: str,
    error_summary: str,
) -> None:
    """Render manual-cleanup guidance for failed group-membership rollback."""
    lines = [
        "Attack-path cleanup did not complete automatically.",
        "",
        f"Target group: {mark_sensitive(target_group or 'unknown', 'group')}",
        f"Added user: {mark_sensitive(added_user or 'unknown', 'user')}",
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


def register_cleanup_from_outcome(
    shell: Any,
    *,
    domain: str,
    outcome: dict[str, Any] | None,
    from_label: str,
    relation: str,
    to_label: str,
) -> bool:
    """Register one deferred cleanup action derived from a step outcome."""
    if not isinstance(outcome, dict):
        return False
    if str(outcome.get("key") or "").strip().lower() != "group_membership_changed":
        return False
    if not bool(outcome.get("cleanup_required", True)):
        return False

    scopes = _get_cleanup_scopes(shell)
    if not scopes:
        return False

    action = {
        "kind": "group_membership_remove",
        "registered_at": _utc_now_iso(),
        "domain": str(domain or "").strip(),
        "target_domain": str(outcome.get("target_domain") or domain or "").strip(),
        "target_group": str(outcome.get("target_group") or "").strip(),
        "added_user": str(outcome.get("added_user") or "").strip(),
        "exec_username": str(outcome.get("exec_username") or "").strip(),
        "exec_password": str(outcome.get("exec_password") or "").strip(),
        "from_label": str(from_label or "").strip(),
        "relation": str(relation or "").strip(),
        "to_label": str(to_label or "").strip(),
    }
    scopes[-1].setdefault("actions", []).append(action)

    # The AddMember seam (``run_exploit_add_member``) already recorded this
    # membership and queued it for the exit cleanup. This scope owns the rollback
    # now (it removes the member when the path ends), so it CLAIMS that record:
    # the exit queue entry is dropped (one revert) and the ledger record is reused
    # (one disclosure), never a second registration of the same change.
    seam_change_id = str(outcome.get("ledger_change_id") or "").strip()
    ledger = ledger_or_warn(shell)
    if seam_change_id:
        from adscan_internal.services.directory_write_ledger import (  # noqa: PLC0415
            claim_directory_write,
        )

        claim_directory_write(shell, seam_change_id)
        action["_ledger_change_id"] = seam_change_id
    elif ledger is not None:
        _change_id = ledger.register_change(
            kind="group_membership_added",
            domain=str(action["domain"]),
            target=f"{action['added_user']} → {action['target_group']}",
            detail={
                "username": action["added_user"],
                "group": action["target_group"],
                "exec_username": action["exec_username"],
                "from_label": action["from_label"],
                "relation": action["relation"],
                "to_label": action["to_label"],
            },
            method=(
                f"BloodHound attack path — {action['relation']}"
                f" ({action['from_label']} → {action['to_label']})"
            ),
        )
        action["_ledger_change_id"] = _change_id

    update_edge_status_by_labels(
        shell,
        domain,
        from_label=action["from_label"],
        relation=action["relation"],
        to_label=action["to_label"],
        status="success",
        notes={
            "cleanup_pending": True,
            "cleanup_kind": "group_membership_remove",
            "cleanup_registered_at": action["registered_at"],
            "cleanup_target_group": action["target_group"],
            "cleanup_added_user": action["added_user"],
        },
    )
    return True


def execute_cleanup_scope(shell: Any, *, scope_id: str) -> bool:
    """Execute and persist all deferred cleanup actions for one scope."""
    scope = _find_cleanup_scope(shell, scope_id)
    if not isinstance(scope, dict):
        return True

    actions = list(scope.get("actions") or [])
    if not actions:
        return True

    all_ok = True
    for action in actions:
        if not isinstance(action, dict):
            continue
        if str(action.get("kind") or "").strip().lower() != "group_membership_remove":
            continue

        domain = str(action.get("domain") or "").strip()
        target_domain = str(action.get("target_domain") or domain).strip() or domain
        target_group = str(action.get("target_group") or "").strip()
        added_user = str(action.get("added_user") or "").strip()
        exec_username = str(action.get("exec_username") or "").strip()
        exec_password = str(action.get("exec_password") or "").strip()
        from_label = str(action.get("from_label") or "").strip()
        relation = str(action.get("relation") or "").strip()
        to_label = str(action.get("to_label") or "").strip()
        cleanup_notes: dict[str, Any] = {
            "cleanup_pending": True,
            "cleanup_kind": "group_membership_remove",
            "cleanup_checked_at": _utc_now_iso(),
            "cleanup_target_group": target_group,
            "cleanup_added_user": added_user,
        }

        remediation_command = (
            f"Remove '{added_user}' from '{target_group}' manually:\n"
            f"  Remove-ADGroupMember -Identity '{target_group}'"
            f" -Members '{added_user}' -Confirm:$false"
        )
        ledger = ledger_or_warn(shell)
        change_id = action.get("_ledger_change_id")
        if ledger is not None and change_id:
            try:
                ledger.set_revert_metadata(
                    change_id,
                    remediation_command=remediation_command,
                    remediation_object_dn=target_group,
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)

        if not (target_group and added_user):
            cleanup_notes.update(
                {
                    "cleanup_status": "failed",
                    "cleanup_error": "Missing cleanup target metadata.",
                }
            )
            update_edge_status_by_labels(
                shell,
                domain,
                from_label=from_label,
                relation=relation,
                to_label=to_label,
                status="success",
                notes=cleanup_notes,
            )
            _mark_group_membership_cleanup_panel(
                target_group=target_group,
                added_user=added_user,
                error_summary="Missing cleanup target metadata.",
            )
            all_ok = False
            if ledger is not None and change_id:
                ledger.mark_manual_required(
                    change_id,
                    reason=_tax.MANUAL_REASON_MISSING_METADATA,
                    remediation_command=remediation_command,
                    remediation_object_dn=target_group,
                    error="Missing cleanup target metadata.",
                )
            continue

        outcome = _revert_group_membership_with_verify(
            shell=shell,
            change_id=change_id,
            domain=domain,
            target_domain=target_domain,
            target_group=target_group,
            added_user=added_user,
            exec_username=exec_username,
            exec_password=exec_password,
        )

        cleanup_ok = outcome == "reverted_confirmed"
        cleanup_notes.update(
            {
                "cleanup_pending": not cleanup_ok,
                "cleanup_status": "success" if cleanup_ok else "failed",
                "cleanup_completed_at": _utc_now_iso(),
                "cleanup_error": "" if cleanup_ok else outcome,
            }
        )
        update_edge_status_by_labels(
            shell,
            domain,
            from_label=from_label,
            relation=relation,
            to_label=to_label,
            status="success",
            notes=cleanup_notes,
        )

        if cleanup_ok:
            try:
                remove_runtime_user_group_membership(
                    shell,
                    target_domain,
                    username=added_user,
                    group_name=target_group,
                    source="group_membership_attack_step",
                    origin_relation="AddMember",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_exception(exception=exc)
            print_info(
                "Attack-path cleanup completed and verified: "
                f"removed {mark_sensitive(added_user, 'user')} from "
                f"{mark_sensitive(target_group, 'group')}."
            )
        else:
            _mark_group_membership_cleanup_panel(
                target_group=target_group,
                added_user=added_user,
                error_summary=outcome or "Automatic group-membership cleanup failed.",
            )
            all_ok = False

    return all_ok


def _revert_group_membership_with_verify(
    *,
    shell: Any,
    change_id: Any,
    domain: str,
    target_domain: str,
    target_group: str,
    added_user: str,
    exec_username: str,
    exec_password: str,
) -> str:
    """Remove the member an attack path added, through the shared revert executor.

    The same executor the exit cleanup and the final pass use
    (:func:`acl_change_cleanup_service.revert_acl_change_now`): the client
    cleanup account, then a verified privileged credential, then the account
    that added the member; bounded retry on a transient failure; every attempt
    recorded on the ledger entry; ``reverted_confirmed`` only after a re-read of
    the group no longer lists the member, ``manual_required`` otherwise.

    Returns ``"reverted_confirmed"`` on success, otherwise a short error string.
    """
    from adscan_internal.services.acl_change_cleanup_service import (  # noqa: PLC0415
        revert_acl_change_now,
    )

    action = {
        "kind": "group_membership_changed",
        "domain": domain,
        "target_domain": target_domain,
        "target": target_group,
        "target_group": target_group,
        "added_user": added_user,
        "exec_username": exec_username,
        "exec_password": exec_password,
        "_ledger_change_id": str(change_id or ""),
    }
    if revert_acl_change_now(shell, action=action):
        return "reverted_confirmed"
    ledger = ledger_or_warn(shell) if change_id else None
    get_change = getattr(ledger, "get_change", None)
    if callable(get_change):
        try:
            entry = get_change(str(change_id)) or {}
            error = str(entry.get("revert_error") or "").strip()
            if error:
                return error
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
    return "Automatic group-membership cleanup failed."
