"""Deferred cleanup helpers for environment-altering attack-path steps."""

from __future__ import annotations

import asyncio
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from adscan_internal import print_info, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_panel
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.attack_graph_service import update_edge_status_by_labels
from adscan_internal.services.cleanup_credential_resolver import (
    looks_like_access_denied,
)
from adscan_internal.services.cleanup_verification import (
    VERIFY_GROUP_MEMBERSHIP,
    verify_group_membership_removed,
)
from adscan_internal.services.environment_change_ledger import MAX_REVERT_ATTEMPTS
from adscan_internal.services.exploitation import ExploitationService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)
from adscan_internal.services.membership_snapshot import (
    remove_runtime_user_group_membership,
)

_CLEANUP_SCOPE_ATTR = "_attack_path_cleanup_scopes"

# Transient exception classes: a stall/timeout/reset where a retry could succeed.
# These MUST pass through the bounded-retry path, never become terminal on the
# first hit. Everything else (constraint, access-denied, no-such-object) is
# definitive and goes straight to manual_required.
_TRANSIENT_EXC = (TimeoutError, asyncio.TimeoutError, ConnectionResetError, ConnectionError)
_TRANSIENT_MARKERS = (
    "timeout",
    "timed out",
    "wait_for",
    "connection reset",
    "connection refused",
    "connection aborted",
    "broken pipe",
    "temporarily unavailable",
)
_REVERT_BACKOFF_SECONDS = 1.5


def _is_transient_failure(error: BaseException | str | None) -> bool:
    """Classify a revert failure as transient (retry) vs definitive (manual)."""
    if isinstance(error, _TRANSIENT_EXC):
        return True
    text = str(error or "").strip().lower()
    if not text:
        return False
    if looks_like_access_denied(text):
        return False
    return any(marker in text for marker in _TRANSIENT_MARKERS)


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
    """Resolve the DC FQDN (or IP last-resort) used for automatic cleanup.

    The rollback runs with ``kerberos=True``, so the host must be a real FQDN for
    the service SPN (CLAUDE.md "Kerberos SPNs — always FQDN"). Routes through the
    ``resolve_dc_fqdn`` SSOT, which promotes a short ``pdc_hostname`` to
    ``<host>.<domain>`` and adds the workspace inventory fallback; a bare IP is
    kept only as the same last resort this helper had before.
    """
    domain_data = (
        getattr(shell, "domains_data", {}).get(domain, {})
        if isinstance(getattr(shell, "domains_data", None), dict)
        else {}
    )
    if not isinstance(domain_data, dict):
        domain_data = {}
    from adscan_internal.models.domain import (  # noqa: PLC0415
        resolve_dc_fqdn,
        resolve_dc_ip,
    )

    return str(
        resolve_dc_fqdn(domain_data, target_domain=domain)
        or resolve_dc_ip(domain_data)
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

    # Register with ledger (stored on shell, optional)
    ledger = getattr(shell, "environment_change_ledger", None)
    if ledger is not None:
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
        pdc_host = _resolve_bloody_cleanup_host(shell, domain=target_domain)
        # Ensure FQDN is target-domain-qualified, not executor-domain-qualified.
        # _resolve_bloody_host in remove_group_member uses the auth domain to
        # append a suffix, which produces the wrong DC when target != auth domain.
        if pdc_host and "." not in pdc_host:
            pdc_host = f"{pdc_host}.{target_domain}"

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
        ledger = getattr(shell, "environment_change_ledger", None)
        change_id = action.get("_ledger_change_id")
        if ledger is not None and change_id:
            try:
                ledger.set_revert_metadata(
                    change_id,
                    remediation_command=remediation_command,
                    remediation_object_dn=target_group,
                    min_credential_principal="original executor",
                )
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)

        if not (
            target_group and added_user and exec_username and exec_password and pdc_host
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
            if ledger is not None and change_id:
                ledger.mark_manual_required(
                    change_id,
                    reason=_tax.MANUAL_REASON_MISSING_METADATA,
                    remediation_command=remediation_command,
                    remediation_object_dn=target_group,
                    error="Missing cleanup credential or target metadata.",
                )
            continue

        outcome = _revert_group_membership_with_verify(
            shell=shell,
            ledger=ledger,
            change_id=change_id,
            pdc_host=pdc_host,
            domain=domain,
            target_domain=target_domain,
            target_group=target_group,
            added_user=added_user,
            exec_username=exec_username,
            exec_password=exec_password,
            remediation_command=remediation_command,
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


def _build_verification_conn(
    shell: Any, *, domain: str, target_domain: str
) -> ADscanLDAPConnection | None:
    """Open a credentialed LDAP connection for the post-revert re-read.

    Reuses the LDAP transport SSOT (LDAPS→LDAP fallback built in). Returns None
    when no DC/credential is available — the caller then fails closed (manual).
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    domain_data = domains_data.get(target_domain) or domains_data.get(domain) or {}
    if not isinstance(domain_data, dict):
        return None
    try:
        from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

        dc_ip = resolve_dc_ip(domain_data)
    except Exception:  # noqa: BLE001
        dc_ip = str(domain_data.get("pdc") or domain_data.get("dc_ip") or "").strip()
    creds = domain_data.get("credentials")
    username = ""
    secret = ""
    if isinstance(creds, dict):
        for stored_user, stored_secret in creds.items():
            if str(stored_secret or "").strip():
                username = str(stored_user)
                secret = str(stored_secret or "").strip()
                break
    if not dc_ip or not username or not secret:
        return None
    is_nt = len(secret) == 32 and all(c in "0123456789abcdefABCDEF" for c in secret)
    config = ADscanLDAPConfig(
        domain=target_domain or domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=None if is_nt else secret,
    )
    try:
        return ADscanLDAPConnection(config)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return None


def _revert_group_membership_with_verify(
    *,
    shell: Any,
    ledger: Any,
    change_id: Any,
    pdc_host: str,
    domain: str,
    target_domain: str,
    target_group: str,
    added_user: str,
    exec_username: str,
    exec_password: str,
    remediation_command: str,
) -> str:
    """Revert a group-membership add with bounded retry + verify-the-undo.

    Returns ``"reverted_confirmed"`` on success, otherwise a short error string
    describing why the change is now ``manual_required``. The ledger is driven
    through ``mark_revert_in_progress`` → (verify) ``mark_reverted_confirmed`` /
    (transient) ``mark_revert_retry`` / (definitive) ``mark_manual_required``.

    A ``TimeoutError`` / transient stall is NEVER swallowed into a terminal state
    on the first hit — it always passes through the bounded-retry budget.
    """
    last_error = "Automatic group-membership cleanup failed."
    for attempt in range(1, MAX_REVERT_ATTEMPTS + 1):
        if ledger is not None and change_id:
            try:
                ledger.mark_revert_in_progress(change_id)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        try:
            result = ExploitationService().acl.remove_group_member(
                pdc_host=pdc_host,
                domain=domain,
                username=exec_username,
                password=exec_password,
                target_group=target_group,
                target_username=added_user,
                kerberos=True,
                target_domain=target_domain,
                timeout=300,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            last_error = str(exc)
            if _is_transient_failure(exc) and ledger is not None and change_id:
                used = ledger.mark_revert_retry(change_id, error=last_error)
                if used < MAX_REVERT_ATTEMPTS:
                    print_warning(
                        f"Transient cleanup failure (attempt {used}/{MAX_REVERT_ATTEMPTS}); "
                        "retrying…"
                    )
                    time.sleep(_REVERT_BACKOFF_SECONDS)
                    continue
                return last_error  # budget exhausted → already manual_required
            # Definitive exception → immediate manual.
            if ledger is not None and change_id:
                ledger.mark_manual_required(
                    change_id,
                    reason=_tax.MANUAL_REASON_REVERT_FAILED,
                    remediation_command=remediation_command,
                    remediation_object_dn=target_group,
                    error=last_error,
                )
            return last_error

        if not bool(result.success):
            last_error = (
                str(result.raw_output or "").strip()
                or "Automatic group-membership cleanup failed."
            )
            if _is_transient_failure(last_error) and ledger is not None and change_id:
                used = ledger.mark_revert_retry(change_id, error=last_error)
                if used < MAX_REVERT_ATTEMPTS:
                    time.sleep(_REVERT_BACKOFF_SECONDS)
                    continue
                return last_error
            if ledger is not None and change_id:
                reason = (
                    _tax.MANUAL_REASON_ACCESS_DENIED
                    if looks_like_access_denied(last_error)
                    else _tax.MANUAL_REASON_REVERT_FAILED
                )
                ledger.mark_manual_required(
                    change_id,
                    reason=reason,
                    remediation_command=remediation_command,
                    remediation_object_dn=target_group,
                    error=last_error,
                )
            return last_error

        # Revert call returned success — VERIFY by re-reading the group.
        confirmed = _verify_group_membership_revert(
            shell, domain=domain, target_domain=target_domain,
            target_group=target_group, added_user=added_user,
        )
        if confirmed:
            if ledger is not None and change_id:
                ledger.mark_reverted_confirmed(
                    change_id,
                    verification_method=VERIFY_GROUP_MEMBERSHIP,
                    min_credential_principal="original executor",
                )
            return "reverted_confirmed"
        # Call said ok, object still dirty (or unverifiable) → manual, fail-closed.
        last_error = "Revert reported success but re-read could not confirm removal."
        print_info_debug(f"cleanup-verify {last_error}")
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_REVERT_FAILED,
                remediation_command=remediation_command,
                remediation_object_dn=target_group,
                error=last_error,
            )
        return last_error

    return last_error


def _verify_group_membership_revert(
    shell: Any,
    *,
    domain: str,
    target_domain: str,
    target_group: str,
    added_user: str,
) -> bool:
    """Open a re-read connection and confirm the member is gone. Fail-closed."""
    conn = _build_verification_conn(shell, domain=domain, target_domain=target_domain)
    if conn is None:
        return False
    try:
        with conn as live:
            return verify_group_membership_removed(
                live, group=target_group, member=added_user
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False
