"""Deferred cleanup helpers for ACL/attribute-level environment changes.

Handles shadow credentials, DACL ACEs, owner changes, SPN injections, and
password resets registered during attack-path exploitation. Mirrors the
structure of attack_path_cleanup_service.py but operates on
shell.acl_cleanup_actions rather than scoped cleanup stacks.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from adscan_internal import print_info, print_warning, telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import cleanup_taxonomy as _tax
from adscan_internal.services.cleanup_credential_resolver import (
    CleanupCredential,
    build_da_escalated_credential,
    looks_like_access_denied,
    resolve_minimal_revert_credential,
)
from adscan_internal.services.cleanup_verification import (
    VERIFY_DACL_ACE,
    VERIFY_GROUP_MEMBERSHIP,
    VERIFY_KEYCREDENTIAL,
    VERIFY_OWNER,
    VERIFY_SPN,
    verify_dacl_ace_removed,
    verify_group_membership_removed,
    verify_keycredential_removed,
    verify_owner_restored,
    verify_spn_removed,
)
from adscan_internal.services.environment_change_ledger import MAX_REVERT_ATTEMPTS
from adscan_internal.services.exploitation import ExploitationService
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)

# Remediation templates are the SSOT in cleanup_taxonomy; re-exported here only
# for back-compat references.
_MANUAL_SHADOW_CREDS = _tax.MANUAL_SHADOW_CREDS
_MANUAL_DACL_ACE = _tax.MANUAL_DACL_ACE
_MANUAL_OWNER = _tax.MANUAL_OWNER
_MANUAL_SPN = _tax.MANUAL_SPN
_MANUAL_PASSWORD = _tax.MANUAL_PASSWORD
_MANUAL_GROUP_MEMBERSHIP = _tax.MANUAL_GROUP_MEMBERSHIP

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


def _resolve_pdc(shell: Any, domain: str) -> str:
    """Resolve the PDC FQDN (or IP last-resort) for a domain from shell.domains_data.

    The reverts driven off this value authenticate with ``kerberos=True``, so the
    host must be a real FQDN for the service SPN (CLAUDE.md "Kerberos SPNs — always
    FQDN"). Routes through the ``resolve_dc_fqdn`` SSOT, which promotes a short
    ``pdc_hostname`` to ``<host>.<domain>`` and adds the workspace inventory
    fallback; a bare IP is kept only as the same last resort the caller had before.
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return ""
    domain_data = domains_data.get(domain) or {}
    if not isinstance(domain_data, dict):
        return ""
    from adscan_internal.models.domain import (  # noqa: PLC0415
        resolve_dc_fqdn,
        resolve_dc_ip,
    )

    return str(
        resolve_dc_fqdn(domain_data, target_domain=domain)
        or resolve_dc_ip(domain_data)
        or ""
    ).strip()


def execute_acl_cleanup(shell: Any) -> None:
    """Execute all deferred ACL/attribute cleanup actions and mark results in the ledger.

    Called from do_exit() before cleanup_workspace_ligolo_artifacts().
    Safe to call when shell.acl_cleanup_actions is missing — exits immediately.
    """
    actions = _resolve_cleanup_actions(shell)
    if not actions:
        return

    ledger = getattr(shell, "environment_change_ledger", None)

    for action in actions:
        if not isinstance(action, dict):
            continue
        kind = str(action.get("kind") or "").strip()
        change_id = action.get("_ledger_change_id")
        target = str(action.get("target") or "").strip()
        domain = str(action.get("domain") or "").strip()
        target_domain = str(action.get("target_domain") or domain).strip() or domain
        credential = resolve_minimal_revert_credential(
            shell,
            action=action,
            domain=domain,
            target_domain=target_domain,
        )

        try:
            _execute_one_action(
                shell=shell,
                ledger=ledger,
                kind=kind,
                change_id=change_id,
                target=target,
                domain=domain,
                target_domain=target_domain,
                credential=credential,
                action=action,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            if ledger is not None and change_id:
                try:
                    ledger.mark_manual_required(
                        change_id,
                        reason=_tax.MANUAL_REASON_REVERT_FAILED,
                        remediation_command=_manual_instructions(kind, action),
                        remediation_object_dn=_object_dn_for(action, target),
                        error=str(exc),
                    )
                except Exception:  # noqa: BLE001
                    pass


def _object_dn_for(action: dict[str, Any], target: str) -> str:
    """Best-known object DN the client acts on (for the manual checklist)."""
    for key in ("target_dn", "object_dn", "dn", "target_object"):
        value = str(action.get(key) or "").strip()
        if value:
            return value
    if str(action.get("kind") or "") == "group_membership_changed":
        return str(action.get("target_group") or target).strip()
    return str(target or "").strip()


def _execute_one_action(
    *,
    shell: Any,
    ledger: Any,
    kind: str,
    change_id: str | None,
    target: str,
    domain: str,
    target_domain: str,
    credential: CleanupCredential,
    action: dict[str, Any],
) -> None:
    """Revert ONE ACL/attribute change with verify-the-undo + bounded retry.

    Builds a per-kind plan (revert callable + verify callable + remediation +
    object DN) and drives it through ``mark_revert_in_progress`` → (verify)
    ``mark_reverted_confirmed`` / (transient) ``mark_revert_retry`` / (definitive
    or unverifiable) ``mark_manual_required``. A ``TimeoutError`` is never
    swallowed into a terminal state on the first hit. Escalation to a stored DA
    credential is LAZY: only after a real ACCESS_DENIED on the minimal principal.
    """
    marked_target = mark_sensitive(target, "user")
    object_dn = _object_dn_for(action, target)
    remediation = _manual_instructions(kind, action)
    if ledger is not None and change_id:
        try:
            ledger.set_revert_metadata(
                change_id,
                remediation_command=remediation,
                remediation_object_dn=object_dn,
                min_credential_principal=credential.principal_label or None,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)

    # password_changed has NO automatic revert — the original secret is gone.
    if kind == "password_changed":
        print_warning(
            f"Password reset cannot be reverted automatically · {marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_NOT_ATTEMPTED,
                remediation_command=_MANUAL_PASSWORD.replace("TARGET", target),
                remediation_object_dn=object_dn,
            )
        return

    pdc_host = _resolve_pdc(shell, target_domain)
    if not pdc_host:
        print_warning(
            f"PDC not found for {target_domain} — cannot revert {kind} · {marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_MISSING_METADATA,
                remediation_command=remediation,
                remediation_object_dn=object_dn,
            )
        return

    if not credential.usable:
        # No minimal principal available. If a privileged-looking credential is
        # stored, use it as the ONLY option (there is no lesser principal to be
        # minimal about); otherwise this is genuinely uncleanable → manual.
        escalated = (
            build_da_escalated_credential(shell, target_domain or domain)
            if credential.can_escalate_to_da
            else None
        )
        if escalated is None or not escalated.usable:
            print_warning(
                f"No usable rollback credential found for {kind} · {marked_target}"
            )
            if ledger is not None and change_id:
                ledger.mark_manual_required(
                    change_id,
                    reason=_tax.MANUAL_REASON_MISSING_CREDENTIAL,
                    remediation_command=remediation,
                    remediation_object_dn=object_dn,
                )
            return
        credential = escalated

    plan = _build_revert_plan(kind=kind, target=target, action=action)
    if plan is None:
        print_warning(f"Unknown ACL cleanup kind '{kind}' — skipping")
        return
    if plan.get("needs_manual"):
        if ledger is not None and change_id:
            ledger.mark_manual_required(
                change_id,
                reason=_tax.MANUAL_REASON_MISSING_METADATA,
                remediation_command=plan.get("remediation") or remediation,
                remediation_object_dn=object_dn,
            )
        return

    _drive_revert_with_verify(
        shell=shell,
        ledger=ledger,
        change_id=change_id,
        kind=kind,
        target=target,
        domain=domain,
        target_domain=target_domain,
        pdc_host=pdc_host,
        credential=credential,
        plan=plan,
        remediation=remediation,
        object_dn=object_dn,
    )


def _build_revert_plan(
    *, kind: str, target: str, action: dict[str, Any]
) -> dict[str, Any] | None:
    """Return a per-kind revert plan, or None for an unknown kind.

    A plan dict carries:
        revert(service, conn_args) -> result    : performs the revert call
        verify(conn) -> bool                     : post-revert re-read (fail-closed)
        verification_method: str                 : ledger verification_method tag
        success_label: str                       : info message on confirm
        needs_manual: bool / remediation: str    : when metadata is missing
    """
    if kind == "shadow_credentials_added":
        added_value = str(action.get("added_key_credential_value") or "").strip()
        if not added_value:
            return {
                "needs_manual": True,
                "remediation": _MANUAL_SHADOW_CREDS,
            }

        def _revert_shadow(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.remove_shadow_credential_value(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_user=target,
                key_credential_value=added_value, kerberos=True, timeout=300,
            )

        return {
            "revert": _revert_shadow,
            "verify": lambda conn: verify_keycredential_removed(
                conn, target=target, key_credential_value=added_value
            ),
            "verification_method": VERIFY_KEYCREDENTIAL,
            "success_label": "Shadow credential value removed",
        }

    if kind == "dacl_ace_added":
        trustee = str(action.get("trustee") or "").strip()
        rights_type = str(action.get("rights_type") or "genericAll").strip()
        trustee_sid = str(action.get("trustee_sid") or "").strip()

        def _revert_dacl(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.remove_dacl_ace(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_object=target, trustee=trustee,
                rights_type=rights_type, kerberos=True, timeout=300,
            )

        def _verify(conn: Any) -> bool:
            # Without the resolved trustee SID we cannot positively confirm the
            # ACE is gone → fail-closed (manual) rather than claim done.
            if not trustee_sid:
                return False
            return verify_dacl_ace_removed(conn, target=target, trustee_sid=trustee_sid)

        rights_label = "DCSync" if rights_type == "dcsync" else "GenericAll"
        return {
            "revert": _revert_dacl,
            "verify": _verify,
            "verification_method": VERIFY_DACL_ACE,
            "success_label": f"DACL ACE removed ({rights_label})",
        }

    if kind == "owner_changed":
        original_owner_sid = action.get("original_owner_sid")
        if not original_owner_sid:
            return {"needs_manual": True, "remediation": _MANUAL_OWNER}

        def _revert_owner(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.restore_owner(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_object=target,
                original_owner_sid=str(original_owner_sid), kerberos=True, timeout=300,
            )

        return {
            "revert": _revert_owner,
            "verify": lambda conn: verify_owner_restored(
                conn, target=target, original_owner_sid=str(original_owner_sid)
            ),
            "verification_method": VERIFY_OWNER,
            "success_label": "Object owner restored",
        }

    if kind == "spn_added":
        spn = str(action.get("spn") or "").strip()

        def _revert_spn(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.clear_service_principal_name(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_user=target, spn=spn,
                kerberos=True, timeout=300,
            )

        return {
            "revert": _revert_spn,
            "verify": lambda conn: verify_spn_removed(conn, target=target, spn=spn),
            "verification_method": VERIFY_SPN,
            "success_label": "SPN cleared",
        }

    if kind == "group_membership_changed":
        target_group = str(action.get("target_group") or target).strip()
        added_user = str(action.get("added_user") or "").strip()
        if not target_group or not added_user:
            return {"needs_manual": True}

        def _revert_group(service: Any, *, pdc_host: str, domain: str, cred: CleanupCredential):
            return service.acl.remove_group_member(
                pdc_host=pdc_host, domain=domain, username=cred.username,
                password=cred.secret, target_group=target_group,
                target_username=added_user, kerberos=True,
                target_domain=str(action.get("target_domain") or domain), timeout=300,
            )

        return {
            "revert": _revert_group,
            "verify": lambda conn: verify_group_membership_removed(
                conn, group=target_group, member=added_user
            ),
            "verification_method": VERIFY_GROUP_MEMBERSHIP,
            "success_label": "Group membership reverted",
        }

    return None


def _build_verification_conn(
    shell: Any, *, domain: str, target_domain: str
) -> ADscanLDAPConnection | None:
    """Open a credentialed LDAP connection for the post-revert re-read.

    Reuses the LDAP transport SSOT (LDAPS→LDAP fallback built in). Returns None
    when no DC/credential is available — the caller then fails closed (manual).
    """
    domains_data = getattr(shell, "domains_data", {}) or {}
    if not isinstance(domains_data, dict):
        return None
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


def _verify_revert(
    shell: Any, *, domain: str, target_domain: str, plan: dict[str, Any]
) -> bool:
    """Open a re-read connection and run the plan's verifier. Fail-closed."""
    verify_fn = plan.get("verify")
    if not callable(verify_fn):
        return False
    conn = _build_verification_conn(shell, domain=domain, target_domain=target_domain)
    if conn is None:
        return False
    try:
        with conn as live:
            return bool(verify_fn(live))
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return False


def _drive_revert_with_verify(
    *,
    shell: Any,
    ledger: Any,
    change_id: str | None,
    kind: str,
    target: str,
    domain: str,
    target_domain: str,
    pdc_host: str,
    credential: CleanupCredential,
    plan: dict[str, Any],
    remediation: str,
    object_dn: str,
) -> None:
    """Bounded-retry + verify-the-undo + lazy DA escalation for one revert."""
    marked_target = mark_sensitive(target, "user")
    service = ExploitationService()
    active = credential
    last_error = "Automatic cleanup returned a non-success result."

    for _ in range(MAX_REVERT_ATTEMPTS + 1):
        if ledger is not None and change_id:
            try:
                ledger.mark_revert_in_progress(change_id)
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
        transient = False
        try:
            result = plan["revert"](
                service, pdc_host=pdc_host, domain=domain, cred=active
            )
            success = bool(getattr(result, "success", False))
            raw = str(getattr(result, "raw_output", "") or "").strip()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            success = False
            raw = str(exc)
            # Track transience from the EXCEPTION TYPE, not the (often opaque)
            # string — a TimeoutError must never be misclassified as definitive.
            transient = _is_transient_failure(exc)

        if not success:
            last_error = raw or last_error
            transient = transient or _is_transient_failure(last_error)
            # Lazy DA escalation only on a real ACCESS_DENIED (not transient).
            if (
                not transient
                and looks_like_access_denied(last_error)
                and not active.is_escalated
                and active.can_escalate_to_da
            ):
                escalated = build_da_escalated_credential(shell, target_domain or domain)
                if escalated is not None and escalated.usable:
                    active = escalated
                    continue
            if transient and ledger is not None and change_id:
                used = ledger.mark_revert_retry(change_id, error=last_error)
                if used < MAX_REVERT_ATTEMPTS:
                    print_warning(
                        f"Transient cleanup failure (attempt {used}/{MAX_REVERT_ATTEMPTS}) "
                        f"· {marked_target}; retrying…"
                    )
                    time.sleep(_REVERT_BACKOFF_SECONDS)
                    continue
                return  # budget exhausted → mark_revert_retry routed to manual
            _manual(
                ledger, change_id, _reason_for(last_error), remediation, object_dn, last_error
            )
            print_warning(f"{plan['success_label']} failed · {marked_target}")
            return

        # Revert call returned success — VERIFY by re-reading the object.
        confirmed = _verify_revert(
            shell, domain=domain, target_domain=target_domain, plan=plan
        )
        if confirmed:
            print_info(f"{plan['success_label']} (verified) · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted_confirmed(
                    change_id,
                    verification_method=str(plan.get("verification_method") or ""),
                    min_credential_principal=active.principal_label or None,
                )
            return
        # Call said ok, object still dirty / unverifiable → manual (fail-closed).
        last_error = "Revert reported success but re-read could not confirm it."
        print_warning(f"Could not verify rollback · {marked_target}")
        _manual(
            ledger, change_id, _tax.MANUAL_REASON_REVERT_FAILED, remediation,
            object_dn, last_error,
        )
        return


def _reason_for(error: str) -> str:
    """Pick the manual_reason discriminator for a definitive revert failure."""
    return (
        _tax.MANUAL_REASON_ACCESS_DENIED
        if looks_like_access_denied(error)
        else _tax.MANUAL_REASON_REVERT_FAILED
    )


def _manual(
    ledger: Any,
    change_id: str | None,
    reason: str,
    remediation: str,
    object_dn: str,
    error: str,
) -> None:
    """Mark a change manual_required (no-op when ledger/change_id absent)."""
    if ledger is None or not change_id:
        return
    ledger.mark_manual_required(
        change_id,
        reason=reason,
        remediation_command=remediation,
        remediation_object_dn=object_dn,
        error=error,
    )


def _manual_instructions(kind: str, action: dict[str, Any]) -> str:
    """Return PowerShell manual remediation instructions for a given change kind."""
    target = str(action.get("target") or "TARGET")
    spn = str(action.get("spn") or "SPN")
    if kind == "shadow_credentials_added":
        return _MANUAL_SHADOW_CREDS
    if kind == "dacl_ace_added":
        return _MANUAL_DACL_ACE
    if kind == "owner_changed":
        return _MANUAL_OWNER
    if kind == "spn_added":
        return _MANUAL_SPN.replace("TARGET", target).replace("SPN", spn)
    if kind == "password_changed":
        return _MANUAL_PASSWORD.replace("TARGET", target)
    if kind == "group_membership_changed":
        group = str(action.get("target_group") or target)
        member = str(action.get("added_user") or "MEMBER")
        return _MANUAL_GROUP_MEMBERSHIP.replace("GROUP", group).replace(
            "MEMBER", member
        )
    return f"Manually revert the '{kind}' change on '{target}'."


def _resolve_cleanup_actions(shell: Any) -> list[dict[str, Any]]:
    """Return in-memory cleanup actions plus pending actions reconstructed from ledger."""
    actions: list[dict[str, Any]] = []
    raw_actions = getattr(shell, "acl_cleanup_actions", None)
    if isinstance(raw_actions, list):
        actions.extend(action for action in raw_actions if isinstance(action, dict))

    seen_ids = {
        str(action.get("_ledger_change_id") or "")
        for action in actions
        if str(action.get("_ledger_change_id") or "")
    }
    ledger = getattr(shell, "environment_change_ledger", None)
    get_changes = getattr(ledger, "get_changes", None)
    if not callable(get_changes):
        return actions
    try:
        changes = get_changes()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return actions
    if not isinstance(changes, list):
        return actions

    for entry in changes:
        if not isinstance(entry, dict):
            continue
        change_id = str(entry.get("change_id") or "").strip()
        if change_id and change_id in seen_ids:
            continue
        status = str(entry.get("revert_status") or "").strip().lower()
        # Re-attempt records that are still pending/in-progress, or that landed in
        # the collapsed manual_required(revert_failed) terminal (legacy "failed").
        retryable = status in {
            _tax.STATUS_PENDING,
            _tax.STATUS_REVERT_IN_PROGRESS,
            _tax.STATUS_REVERT_FAILED_RETRYING,
            _tax.STATUS_LEGACY_FAILED,
        } or (
            status == _tax.STATUS_MANUAL_REQUIRED
            and str(entry.get("manual_reason") or "") == _tax.MANUAL_REASON_REVERT_FAILED
        )
        if not retryable:
            continue
        action = _cleanup_action_from_ledger_entry(entry)
        if action:
            actions.append(action)
            if change_id:
                seen_ids.add(change_id)
    return actions


def _cleanup_action_from_ledger_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Build one cleanup action from persisted environment ledger metadata."""
    kind = str(entry.get("kind") or "").strip()
    if kind not in {
        "shadow_credentials_added",
        "dacl_ace_added",
        "owner_changed",
        "spn_added",
        "password_changed",
        "group_membership_changed",
    }:
        return None
    detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
    action = {
        "kind": kind,
        "domain": str(entry.get("domain") or detail.get("domain") or "").strip(),
        "target_domain": str(
            detail.get("target_domain") or entry.get("domain") or ""
        ).strip(),
        "target": str(detail.get("target_object") or entry.get("target") or "").strip(),
        "exec_username": str(
            detail.get("exec_username") or detail.get("executor_username") or ""
        ).strip(),
        "_ledger_change_id": str(entry.get("change_id") or "").strip(),
    }
    for key in (
        "trustee",
        "rights_type",
        "original_owner_sid",
        "spn",
        "target_user",
        "added_key_credential_value",
        "target_group",
        "added_user",
    ):
        if key in detail:
            action[key] = detail[key]
    if kind == "password_changed" and detail.get("target_user"):
        action["target"] = str(detail.get("target_user") or "").strip()
    return action


