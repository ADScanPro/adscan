"""Deferred cleanup helpers for ACL/attribute-level environment changes.

Handles shadow credentials, DACL ACEs, owner changes, SPN injections, and
password resets registered during attack-path exploitation. Mirrors the
structure of attack_path_cleanup_service.py but operates on
shell.acl_cleanup_actions rather than scoped cleanup stacks.
"""

from __future__ import annotations

from typing import Any

from adscan_internal import print_info, print_warning, telemetry
from adscan_internal.principal_utils import normalize_machine_account
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.exploitation import ExploitationService


_MANUAL_SHADOW_CREDS = (
    "Review msDS-KeyCredentialLink on the target and remove only the ADscan-created "
    "KeyCredential value. Do not clear the whole attribute unless the client has "
    "confirmed there are no legitimate Windows Hello for Business or other PKINIT "
    "credentials on the object."
)

_MANUAL_DACL_ACE = (
    "Remove the ACL entry added by ADscan manually:\n"
    "  Remove-DomainObjectAcl -Rights All -TargetIdentity TARGET"
    " -PrincipalIdentity TRUSTEE"
)

_MANUAL_OWNER = (
    "Restore the original owner of the object manually:\n"
    "  $sd = Get-ADObject TARGET -Properties ntSecurityDescriptor\n"
    "  $sd.ntSecurityDescriptor.SetOwner([System.Security.Principal.NTAccount]'ORIGINAL_OWNER')\n"
    "  Set-ADObject TARGET -Replace @{ntSecurityDescriptor=$sd.ntSecurityDescriptor}"
)

_MANUAL_SPN = (
    "Remove the injected SPN manually:\n"
    "  Set-ADUser -Identity TARGET -ServicePrincipalNames @{Remove='SPN'}\n"
    "  or: Set-ADComputer -Identity TARGET -ServicePrincipalNames @{Remove='SPN'}"
)

_MANUAL_PASSWORD = (
    "Coordinate with the client to reset the target account password to a known value:\n"
    "  Set-ADAccountPassword -Identity TARGET -NewPassword"
    " (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)\n"
    "  This account's previous credential has been permanently replaced."
)

_MANUAL_GROUP_MEMBERSHIP = (
    "Remove the group member added by ADscan manually:\n"
    "  Remove-ADGroupMember -Identity 'GROUP' -Members 'MEMBER' -Confirm:$false"
)


def _resolve_pdc(shell: Any, domain: str) -> str:
    """Resolve the PDC hostname/IP for a domain from shell.domains_data."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return ""
    domain_data = domains_data.get(domain) or {}
    if not isinstance(domain_data, dict):
        return ""
    return str(
        domain_data.get("pdc_hostname_fqdn")
        or domain_data.get("pdc_hostname")
        or domain_data.get("pdc")
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
        exec_username = str(action.get("exec_username") or "").strip()
        exec_password = str(action.get("exec_password") or "").strip()
        exec_username, exec_password = _resolve_cleanup_credential(
            shell,
            action=action,
            domain=domain,
            target_domain=target_domain,
            exec_username=exec_username,
            exec_password=exec_password,
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
                exec_username=exec_username,
                exec_password=exec_password,
                action=action,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            if ledger is not None and change_id:
                try:
                    ledger.mark_failed(
                        change_id,
                        error=str(exc),
                        manual_cleanup_instructions=_manual_instructions(kind, action),
                    )
                except Exception:  # noqa: BLE001
                    pass


def _execute_one_action(
    *,
    shell: Any,
    ledger: Any,
    kind: str,
    change_id: str | None,
    target: str,
    domain: str,
    target_domain: str,
    exec_username: str,
    exec_password: str,
    action: dict[str, Any],
) -> None:
    marked_target = mark_sensitive(target, "user")

    if kind == "password_changed":
        print_warning(
            f"Password reset cannot be reverted automatically · {marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_operator_required(
                change_id,
                manual_cleanup_instructions=_MANUAL_PASSWORD.replace("TARGET", target),
            )
        return

    pdc_host = _resolve_pdc(shell, target_domain)
    if not pdc_host:
        print_warning(
            f"PDC not found for {target_domain} — cannot revert {kind} · {marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_operator_required(
                change_id,
                manual_cleanup_instructions=_manual_instructions(kind, action),
            )
        return

    if not exec_username or not exec_password:
        print_warning(
            f"No usable rollback credential found for {kind} · {marked_target}"
        )
        if ledger is not None and change_id:
            ledger.mark_operator_required(
                change_id,
                manual_cleanup_instructions=_manual_instructions(kind, action),
            )
        return

    service = ExploitationService()

    if kind == "shadow_credentials_added":
        added_value = str(action.get("added_key_credential_value") or "").strip()
        if not added_value:
            print_warning(
                f"Shadow credentials cleanup needs manual review · {marked_target}"
            )
            if ledger is not None and change_id:
                ledger.mark_operator_required(
                    change_id,
                    manual_cleanup_instructions=(
                        "ADscan does not have the exact msDS-KeyCredentialLink value "
                        "that it added, so it will not clear the whole attribute automatically. "
                        "Review msDS-KeyCredentialLink on the target and remove only the ADscan-created value."
                    ),
                )
            return
        result = service.acl.remove_shadow_credential_value(
            pdc_host=pdc_host,
            domain=domain,
            username=exec_username,
            password=exec_password,
            target_user=target,
            key_credential_value=added_value,
            kerberos=True,
            timeout=300,
        )
        if result.success:
            print_info(f"Shadow credential value removed · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted(change_id)
        else:
            print_warning(f"Shadow credential value removal failed · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_failed(
                    change_id,
                    error=str(result.raw_output or "LDAP rollback returned false"),
                    manual_cleanup_instructions=_MANUAL_SHADOW_CREDS,
                )
        return

    if kind == "dacl_ace_added":
        trustee = str(action.get("trustee") or "").strip()
        rights_type = str(action.get("rights_type") or "genericAll").strip()
        result = service.acl.remove_dacl_ace(
            pdc_host=pdc_host,
            domain=domain,
            username=exec_username,
            password=exec_password,
            target_object=target,
            trustee=trustee,
            rights_type=rights_type,
            kerberos=True,
            timeout=300,
        )
        if result.success:
            rights_label = "DCSync" if rights_type == "dcsync" else "GenericAll"
            print_info(f"DACL ACE removed ({rights_label}) · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted(change_id)
        else:
            print_warning(f"DACL ACE removal failed · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_failed(
                    change_id,
                    error=str(result.raw_output or "native LDAP returned non-zero"),
                    manual_cleanup_instructions=_MANUAL_DACL_ACE,
                )

    elif kind == "owner_changed":
        original_owner_sid = action.get("original_owner_sid")
        if not original_owner_sid:
            print_warning(
                f"Original owner unknown — manual action required · {marked_target}"
            )
            if ledger is not None and change_id:
                ledger.mark_operator_required(
                    change_id,
                    manual_cleanup_instructions=_MANUAL_OWNER,
                )
            return
        result = service.acl.restore_owner(
            pdc_host=pdc_host,
            domain=domain,
            username=exec_username,
            password=exec_password,
            target_object=target,
            original_owner_sid=str(original_owner_sid),
            kerberos=True,
            timeout=300,
        )
        if result.success:
            print_info(f"Object owner restored · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted(change_id)
        else:
            print_warning(f"Owner restoration failed · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_failed(
                    change_id,
                    error=str(result.raw_output or "native LDAP returned non-zero"),
                    manual_cleanup_instructions=_MANUAL_OWNER,
                )

    elif kind == "spn_added":
        spn = str(action.get("spn") or "").strip()
        result = service.acl.clear_service_principal_name(
            pdc_host=pdc_host,
            domain=domain,
            username=exec_username,
            password=exec_password,
            target_user=target,
            spn=spn,
            kerberos=True,
            timeout=300,
        )
        if result.success:
            print_info(f"SPN cleared · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted(change_id)
        else:
            print_warning(f"SPN clear failed · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_failed(
                    change_id,
                    error=str(result.raw_output or "native LDAP returned non-zero"),
                    manual_cleanup_instructions=_MANUAL_SPN.replace(
                        "TARGET", target
                    ).replace("SPN", spn),
                )

    elif kind == "group_membership_changed":
        target_group = str(action.get("target_group") or target).strip()
        added_user = str(action.get("added_user") or "").strip()
        if not target_group or not added_user:
            print_warning(
                f"Group membership cleanup needs manual review · {marked_target}"
            )
            if ledger is not None and change_id:
                ledger.mark_operator_required(
                    change_id,
                    manual_cleanup_instructions=_manual_instructions(kind, action),
                )
            return
        result = service.acl.remove_group_member(
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
        if result.success:
            print_info(f"Group membership reverted · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_reverted(change_id)
        else:
            print_warning(f"Group membership removal failed · {marked_target}")
            if ledger is not None and change_id:
                ledger.mark_failed(
                    change_id,
                    error=str(result.raw_output or "native LDAP returned non-zero"),
                    manual_cleanup_instructions=_manual_instructions(kind, action),
                )

    else:
        print_warning(f"Unknown ACL cleanup kind '{kind}' — skipping")


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
        if str(entry.get("revert_status") or "").strip().lower() not in {
            "pending",
            "failed",
        }:
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


def _lookup_domain_credential(shell: Any, domain: str, username: str) -> str:
    """Resolve one stored credential by username from shell.domains_data."""
    if not domain or not username:
        return ""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return ""
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return ""
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return ""
    wanted = _normalize_credential_username(username)
    for stored_user, stored_secret in creds.items():
        if _normalize_credential_username(str(stored_user)) == wanted:
            return str(stored_secret or "").strip()
    return ""


def _normalize_credential_username(username: str) -> str:
    """Normalize usernames for stored credential lookup."""
    value = str(username or "").strip()
    if "\\" in value:
        value = value.split("\\", 1)[1]
    if "@" in value:
        value = value.split("@", 1)[0]
    if value.endswith("$"):
        return normalize_machine_account(value).lower()
    return value.lower()


def _resolve_cleanup_credential(
    shell: Any,
    *,
    action: dict[str, Any],
    domain: str,
    target_domain: str,
    exec_username: str,
    exec_password: str,
) -> tuple[str, str]:
    """Resolve rollback credentials, preferring the original executor."""
    if exec_username and exec_password:
        return exec_username, exec_password

    if exec_username:
        for lookup_domain in (domain, target_domain):
            resolved = _lookup_domain_credential(shell, lookup_domain, exec_username)
            if resolved:
                print_info_debug(
                    "[acl-cleanup] rollback credential resolved from stored original executor: "
                    f"user={mark_sensitive(exec_username, 'user')} "
                    f"domain={mark_sensitive(lookup_domain, 'domain')}"
                )
                return exec_username, resolved

    fallback = _resolve_fallback_admin_credential(shell, target_domain or domain)
    if fallback:
        fallback_user, fallback_secret = fallback
        print_info_debug(
            "[acl-cleanup] rollback credential falling back to stored privileged-looking credential: "
            f"user={mark_sensitive(fallback_user, 'user')} "
            f"domain={mark_sensitive(target_domain or domain, 'domain')}"
        )
        return fallback_user, fallback_secret

    return exec_username, exec_password


def _resolve_fallback_admin_credential(
    shell: Any, domain: str
) -> tuple[str, str] | None:
    """Return a conservative stored admin-looking credential for rollback fallback."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return None
    priority_names = (
        "administrator",
        "admin",
        "domain.admin",
        "da",
    )
    for wanted in priority_names:
        for stored_user, stored_secret in creds.items():
            if _normalize_credential_username(str(stored_user)) == wanted:
                secret = str(stored_secret or "").strip()
                if secret:
                    return str(stored_user), secret
    return None
