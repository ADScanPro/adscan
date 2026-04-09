"""Deferred cleanup helpers for environment-altering attack-path steps."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import secrets

from adscan_internal import print_info, telemetry
from adscan_internal.rich_output import mark_sensitive, print_panel
from adscan_internal.services.attack_graph_service import update_edge_status_by_labels
from adscan_internal.services.exploitation import ExploitationService

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


def _resolve_bloody_cleanup_host(shell: Any, *, domain: str) -> str:
    """Resolve the DC host used for automatic cleanup."""
    domain_data = (
        getattr(shell, "domains_data", {}).get(domain, {})
        if isinstance(getattr(shell, "domains_data", None), dict)
        else {}
    )
    if not isinstance(domain_data, dict):
        domain_data = {}
    return str(
        domain_data.get("pdc_hostname_fqdn")
        or domain_data.get("pdc_hostname")
        or domain_data.get("pdc")
        or ""
    ).strip()


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
        bloody_path = str(getattr(shell, "bloodyad_path", "") or "").strip()
        pdc_host = _resolve_bloody_cleanup_host(shell, domain=target_domain)

        cleanup_notes: dict[str, Any] = {
            "cleanup_pending": True,
            "cleanup_kind": "group_membership_remove",
            "cleanup_checked_at": _utc_now_iso(),
            "cleanup_target_group": target_group,
            "cleanup_added_user": added_user,
        }

        if not (
            target_group
            and added_user
            and exec_username
            and exec_password
            and bloody_path
            and pdc_host
        ):
            cleanup_notes.update(
                {
                    "cleanup_status": "failed",
                    "cleanup_error": "Missing cleanup credential or target metadata.",
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
                error_summary="Missing cleanup credential or target metadata.",
            )
            all_ok = False
            continue

        try:
            result = ExploitationService().acl.remove_group_member(
                pdc_host=pdc_host,
                bloody_path=bloody_path,
                domain=domain,
                username=exec_username,
                password=exec_password,
                target_group=target_group,
                target_username=added_user,
                kerberos=True,
                timeout=300,
            )
            cleanup_ok = bool(result.success)
            cleanup_notes.update(
                {
                    "cleanup_pending": not cleanup_ok,
                    "cleanup_status": "success" if cleanup_ok else "failed",
                    "cleanup_completed_at": _utc_now_iso(),
                    "cleanup_error": "" if cleanup_ok else str(result.raw_output or "").strip(),
                    "cleanup_already_absent": bool(getattr(result, "already_absent", False)),
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
                print_info(
                    "Attack-path cleanup completed: "
                    f"removed {mark_sensitive(added_user, 'user')} from "
                    f"{mark_sensitive(target_group, 'group')}."
                )
            else:
                _mark_group_membership_cleanup_panel(
                    target_group=target_group,
                    added_user=added_user,
                    error_summary=str(result.raw_output or "").strip()
                    or "Automatic group-membership cleanup failed.",
                )
                all_ok = False
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            cleanup_notes.update(
                {
                    "cleanup_status": "failed",
                    "cleanup_error": str(exc),
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
                error_summary=str(exc),
            )
            all_ok = False

    return all_ok
