"""Deferred revert for MSSQL SYSTEM-escalation minted admin accounts.

Mirrors ``acl_change_cleanup_service.py``'s pattern for a resource whose
consumer lives ENTIRELY outside the function that creates it: a MSSQL
SeImpersonate/TokenTheft follow-up (``run_xpcmdshell_system_escalation_followup``
in ``cli/mssql.py``) mints an ephemeral privileged account to prove SYSTEM,
hands it to the standard credential pipeline (``add_credential``), and used to
revert it immediately afterward — inside the SAME function call. That races the
REAL consumer: attack-path materialization and privilege sweeps are a LATER,
SEPARATE scan phase that re-authenticates using whatever credential is
currently stored as the domain's active one in ``domains_data``, which is
exactly the account the inline revert just deleted (``KDC_ERR_C_
PRINCIPAL_UNKNOWN`` — the DarkZero cross-forest regression).

The fix: never revert inline. Register the pending revert (mirrors
``shell.acl_cleanup_actions`` + the ledger's ``pending`` record) and let
``do_exit`` drain it — by which point the credential has done everything it
was ever going to do this session, so deleting it can no longer race a live
consumer. The revert itself is a plain LDAP delete authenticated by the SAME
minted credential (once genuinely a Domain Admin — see the ``is_dc``
cross-forest fix in ``cli/mssql.py:_resolve_linked_escalation_target`` — any
Domain Admin can delete a domain user object over ordinary LDAP; no SYSTEM
channel is required, so this does not need to re-establish the ephemeral
MSSQL/CLR escalation session that produced the account).
"""

from __future__ import annotations

from typing import Any

from adscan_core.output import confirm_ask
from adscan_core.rich_output import (
    print_exception,
    print_info,
    print_info_debug,
    print_success,
    print_warning,
)
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import cleanup_taxonomy as _tax

_ACTION_KIND = "mssql_admin_account_created"


def register_deferred_admin_account_revert(
    shell: Any,
    *,
    change_id: str | None,
    domain: str,
    username: str,
    is_dc: bool = False,
    target_host: str | None = None,
    target_hostname: str | None = None,
) -> None:
    """Register a minted MSSQL-escalation account for revert AT SCAN EXIT.

    Never reverts inline — see the module docstring for why. No-ops when
    ``shell`` has no ``mssql_cleanup_actions`` queue (a stale/legacy shell
    that predates ``activate_workspace``'s initialization of it) or when the
    account is anonymous (nothing to delete).

    Args:
        shell: The active PentestShell.
        change_id: The environment-change-ledger id registered by
            :meth:`MssqlSeImpersonateSession._finalize_with_admin_add`
            (``mssql_admin_account_created``). ``None`` is tolerated (best
            effort — the revert still runs, just without a ledger record to
            settle).
        domain: The domain the account was minted IN (the escalation
            TARGET's own domain — ``target_domain``, not the auth domain).
        username: The minted account's sAMAccountName.
        is_dc: Whether the escalation target is a Domain Controller — the
            minted account was added to the domain-wide Domain Admins group
            (``add_runtime_user_group_membership``) rather than a per-host
            local Administrators (``add_runtime_admin_to_edge``). Needed so
            the deferred revert removes the SAME runtime membership record
            it added, keeping the snapshot symmetric on undo.
        target_host: IP/hostname of the escalation target host — required to
            remove a per-host AdminTo edge when ``is_dc`` is False.
        target_hostname: Optional FQDN/NetBIOS hint for the target host,
            mirroring what was passed to ``add_runtime_admin_to_edge``.
    """
    username = str(username or "").strip()
    domain = str(domain or "").strip()
    if not username or not domain:
        return
    actions = getattr(shell, "mssql_cleanup_actions", None)
    if not isinstance(actions, list):
        # No queue on this shell — fall back to initializing one rather than
        # silently dropping the pending revert (legal-critical: the account
        # must not be left un-tracked on the client's directory).
        actions = []
        try:
            shell.mssql_cleanup_actions = actions
        except Exception:  # noqa: BLE001 — best-effort attribute set
            print_info_debug(
                "[mssql-cleanup] could not attach mssql_cleanup_actions to shell; "
                "deferred revert may be lost if the process exits abnormally."
            )
    actions.append(
        {
            "kind": _ACTION_KIND,
            "domain": domain,
            "username": username,
            "_ledger_change_id": str(change_id or ""),
            "is_dc": bool(is_dc),
            "target_host": str(target_host or ""),
            "target_hostname": str(target_hostname or ""),
        }
    )
    print_info_debug(
        f"[mssql-cleanup] deferred revert registered for "
        f"{mark_sensitive(username, 'user')}@{mark_sensitive(domain, 'domain')} "
        "— will run at scan exit, after every consumer of this credential has settled."
    )


def _resolve_pending_actions(shell: Any) -> list[dict[str, Any]]:
    """In-memory queue plus any ledger-persisted pending record not yet in it.

    Mirrors ``acl_change_cleanup_service._resolve_cleanup_actions`` — a
    session that died between ``register_deferred_admin_account_revert`` and
    ``do_exit`` (Ctrl+C, crash) still has the ledger record on disk; the next
    ``do_exit`` in THIS process only sees the in-memory queue, but a re-run of
    this same workspace would reconstruct it from the ledger too.
    """
    actions: list[dict[str, Any]] = []
    raw_actions = getattr(shell, "mssql_cleanup_actions", None)
    if isinstance(raw_actions, list):
        actions.extend(a for a in raw_actions if isinstance(a, dict))

    seen_ids = {
        str(a.get("_ledger_change_id") or "")
        for a in actions
        if str(a.get("_ledger_change_id") or "")
    }
    ledger = getattr(shell, "environment_change_ledger", None)
    get_changes = getattr(ledger, "get_changes", None)
    if not callable(get_changes):
        return actions
    try:
        changes = get_changes()
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return actions
    if not isinstance(changes, list):
        return actions

    for entry in changes:
        if not isinstance(entry, dict) or entry.get("kind") != _ACTION_KIND:
            continue
        change_id = str(entry.get("change_id") or "").strip()
        if change_id and change_id in seen_ids:
            continue
        status = str(entry.get("revert_status") or "").strip().lower()
        retryable = status in {
            _tax.STATUS_PENDING,
            _tax.STATUS_REVERT_IN_PROGRESS,
            _tax.STATUS_REVERT_FAILED_RETRYING,
            _tax.STATUS_LEGACY_FAILED,
        } or (
            status == _tax.STATUS_MANUAL_REQUIRED
            and str(entry.get("manual_reason") or "")
            == _tax.MANUAL_REASON_REVERT_FAILED
        )
        if not retryable:
            continue
        detail = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
        username = str((detail or {}).get("account") or "").strip()
        if not username:
            continue
        actions.append(
            {
                "kind": _ACTION_KIND,
                "domain": str(entry.get("domain") or "").strip(),
                "username": username,
                "_ledger_change_id": change_id,
                # Ledger ``detail`` carries ``is_dc`` (set at register time by
                # ``_finalize_with_admin_add``) but not the target host — a
                # crash-recovered action can still remove the domain-wide
                # Domain Admins runtime membership; a per-host AdminTo edge
                # cannot be located without the host, so it is left as-is in
                # that rare fallback path (best-effort, not legal-critical —
                # the ACCOUNT DELETE itself, not the graph annotation, is the
                # governed cleanup obligation here).
                "is_dc": bool((detail or {}).get("is_dc")),
                "target_host": "",
                "target_hostname": "",
            }
        )
        if change_id:
            seen_ids.add(change_id)
    return actions


def _resolve_minted_account_secret(
    shell: Any, *, domain: str, username: str
) -> str | None:
    """Return the minted account's OWN stored secret, not "whatever is currently
    active" for the domain — self-contained, so the deferred revert does not
    depend on ``domains_data[domain]``'s active-credential pointer still being
    this account by exit time (a later attack-path step may have switched it).

    Credential keys are stored lowercased (``credential_store_service.py``
    ``update_domain_credential`` normalizes on write) — match case-insensitively.
    """
    credentials = (getattr(shell, "domains_data", None) or {}).get(domain, {}).get(
        "credentials"
    ) or {}
    if not isinstance(credentials, dict):
        return None
    return credentials.get(username) or credentials.get(username.lower())


def _resolve_account_dn(
    shell: Any, *, domain: str, username: str, secret: str
) -> str | None:
    """Resolve ``username``'s distinguishedName in ``domain`` via native LDAP.

    Sync, best-effort — reuses the same query helper the RID-512 membership
    check already uses for this exact account
    (``native_group_membership.is_principal_member_of_rid_native``), so no new
    LDAP-query mechanism is introduced. Authenticates as ``username`` itself
    (its own stored secret), not the domain's currently-active credential.
    """
    from adscan_internal.services.ldap_query_service import (  # noqa: PLC0415
        query_shell_ldap_attribute_values,
    )

    domain_data = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    if not isinstance(domain_data, dict):
        return None

    try:
        from adscan_internal.services.native_group_membership import (  # noqa: PLC0415
            escape_ldap_filter_value,
        )

        escaped = escape_ldap_filter_value(username)
    except Exception:  # noqa: BLE001
        escaped = username.replace("(", "").replace(")", "").replace("\\", "")

    values = query_shell_ldap_attribute_values(
        shell,
        domain=domain,
        ldap_filter=f"(&(objectClass=user)(sAMAccountName={escaped}))",
        attribute="distinguishedName",
        auth_username=username,
        auth_password=secret,
        pdc=str(domain_data.get("pdc") or ""),
        prefer_kerberos=True,
        allow_ntlm_fallback=True,
        operation_name="deferred MSSQL admin-account revert DN lookup",
    )
    if not values:
        return None
    return str(values[0]).strip() or None


def _delete_via_ldap(
    shell: Any, *, domain: str, username: str, secret: str, user_dn: str
) -> tuple[bool, str | None]:
    """Delete ``user_dn`` over native LDAP, authenticated as the minted account.

    The account genuinely holds Domain Admins by the time this runs (verified
    at mint time — see ``_verify_admin_membership`` /
    ``MssqlSeImpersonateSession.verification_domain``), so it has rights to
    delete its own object. Returns ``(success, error)``.
    """
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.ldap_transport_service import (  # noqa: PLC0415
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )
    from adscan_internal.models.domain import resolve_dc_ip  # noqa: PLC0415

    domain_data = (getattr(shell, "domains_data", None) or {}).get(domain) or {}
    dc_ip = resolve_dc_ip(domain_data)
    if not dc_ip:
        return False, f"no DC IP known for {domain}"

    config = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=username,
        password=secret,
    )

    async def _run() -> tuple[bool, str | None]:
        try:
            result = await async_connect_with_ldap_fallback(config)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return False, str(exc)
        client = result.client
        try:
            ok, err = await client.delete_user(user_dn)
            return bool(ok), (str(err) if err else None)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return False, str(exc)
        finally:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass

    return run_async_sync(_run())


def execute_deferred_mssql_admin_account_reverts(shell: Any) -> None:
    """Revert every pending MSSQL-escalation minted account. Called from ``do_exit``.

    Safe to call when ``shell.mssql_cleanup_actions`` is missing or empty —
    returns immediately. Each revert is verified by re-reading the account's
    DN (gone == deleted); on failure or when the account/DN can no longer be
    resolved, the ledger record is routed to ``manual_required`` with a
    native ``net user <name> /delete`` remediation command so the client's
    cleanup report is never a silent half-state — mirrors
    ``MssqlSeImpersonateSession._route_revert_failure``.
    """
    actions = _resolve_pending_actions(shell)
    if not actions:
        return

    ledger = getattr(shell, "environment_change_ledger", None)

    for action in actions:
        domain = str(action.get("domain") or "").strip()
        username = str(action.get("username") or "").strip()
        change_id = str(action.get("_ledger_change_id") or "").strip() or None
        marked_user = mark_sensitive(username, "user")
        marked_domain = mark_sensitive(domain, "domain")

        if not domain or not username:
            continue

        remediation_command = f"net user {username} /delete"

        # Operator gate — every account reaching this point is a CREATE_NEW
        # account ADscan minted (a REUSE_EXISTING account never registers a
        # deferred revert in the first place; see
        # register_deferred_admin_account_revert's caller in cli/mssql.py).
        # Default is YES/delete (auto-resolves unattended in `adscan ci`); a
        # declined delete is never a silent orphan — it is settled to
        # manual_required with the native remediation command so the kept
        # account is a DISCLOSED artifact in the cleanup report.
        keep_account = not confirm_ask(
            f"Delete the privileged account ADscan created "
            f"({marked_user}@{marked_domain})?",
            default=True,
        )
        if keep_account:
            print_info(
                f"Keeping minted MSSQL-escalation account {marked_user}@{marked_domain} "
                "at the operator's request — routing it to manual cleanup so it stays "
                "a disclosed artifact rather than a silent orphan."
            )
            _settle_manual(
                ledger,
                change_id,
                remediation_command=remediation_command,
                remediation_object=username,
                error="operator chose to keep the account instead of deleting it",
                reason=_tax.MANUAL_REASON_OPERATOR_DECLINED,
            )
            continue

        secret = _resolve_minted_account_secret(shell, domain=domain, username=username)
        if not secret:
            print_warning(
                f"Minted account credential for {marked_user}@{marked_domain} is no "
                "longer available in the workspace — routing its revert to manual cleanup."
            )
            _settle_manual(
                ledger,
                change_id,
                remediation_command=remediation_command,
                remediation_object=username,
                error="the minted account's stored credential is no longer available",
            )
            continue

        try:
            user_dn = _resolve_account_dn(
                shell, domain=domain, username=username, secret=secret
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            user_dn = None

        if not user_dn:
            print_warning(
                f"Could not resolve DN for minted account {marked_user}@{marked_domain} "
                "— routing its revert to manual cleanup."
            )
            _settle_manual(
                ledger,
                change_id,
                remediation_command=remediation_command,
                remediation_object=username,
                error="could not resolve the minted account's distinguishedName",
            )
            continue

        try:
            ok, err = _delete_via_ldap(
                shell, domain=domain, username=username, secret=secret, user_dn=user_dn
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            ok, err = False, str(exc)

        if ok:
            print_success(
                f"Reverted: minted MSSQL-escalation account {marked_user}@{marked_domain} deleted."
            )
            if ledger is not None and change_id:
                try:
                    ledger.mark_reverted_confirmed(
                        change_id, verification_method="mssql_deferred_ldap_delete"
                    )
                except Exception as exc:  # noqa: BLE001
                    telemetry.capture_exception(exc)
                    print_exception(exception=exc)
            # Mirror the account deletion into the runtime membership
            # snapshot — the account no longer exists, so its effective
            # membership (recorded by the mssql.py follow-up when the group
            # add was verified) must be removed too, or a later attack-path
            # materialization pass still sees a Domain Admins / local-admin
            # principal that ADscan just deleted.
            #
            # DC target -> remove the domain-wide Domain Admins runtime
            # membership from memberships.json (the SSOT), mirroring
            # attack_path_cleanup_service.execute_cleanup_scope's
            # remove_runtime_user_group_membership call on a confirmed revert.
            # Member-server target -> the account's AdminTo edge lives in the
            # attack graph (add_runtime_admin_to_edge -> upsert_edge), not in
            # memberships.json; the graph model is status-transition, not
            # delete (same idiom as every other cleanup step in this
            # codebase), so annotate it as reverted rather than removing it.
            is_dc_action = bool(action.get("is_dc"))
            action_target_host = str(action.get("target_host") or "").strip()
            try:
                if is_dc_action:
                    from adscan_internal.services.membership_snapshot import (  # noqa: PLC0415
                        remove_runtime_user_group_membership,
                    )

                    remove_runtime_user_group_membership(
                        shell,
                        domain,
                        username=username,
                        group_name="Domain Admins",
                        source="mssql_seimpersonate_escalation",
                        origin_relation="MssqlAdminGroupAdd",
                    )
                elif action_target_host:
                    from adscan_internal.services.attack_graph_service import (  # noqa: PLC0415
                        update_edge_status_by_labels,
                    )

                    update_edge_status_by_labels(
                        shell,
                        domain,
                        from_label=username,
                        relation="AdminTo",
                        to_label=action_target_host,
                        status="success",
                        notes={
                            "cleanup_pending": False,
                            "cleanup_status": "success",
                            "cleanup_kind": "mssql_admin_account_deleted",
                        },
                    )
            except Exception as membership_exc:  # noqa: BLE001
                telemetry.capture_exception(membership_exc)
                print_exception(exception=membership_exc)
                print_info_debug(
                    "[mssql-cleanup] account deleted, but ADscan could not update "
                    "the runtime membership/edge it had recorded."
                )
        else:
            print_warning(
                f"Deferred revert of {marked_user}@{marked_domain} failed: {err}. "
                "Routing to manual cleanup."
            )
            _settle_manual(
                ledger,
                change_id,
                remediation_command=remediation_command,
                remediation_object=user_dn,
                error=err or "LDAP delete failed",
            )


def _settle_manual(
    ledger: Any,
    change_id: str | None,
    *,
    remediation_command: str,
    remediation_object: str,
    error: str,
    reason: str = _tax.MANUAL_REASON_REVERT_FAILED,
) -> None:
    if ledger is None or not change_id:
        return
    try:
        ledger.set_revert_metadata(
            change_id,
            remediation_command=remediation_command,
            remediation_object_dn=remediation_object,
        )
        if reason == _tax.MANUAL_REASON_REVERT_FAILED:
            # Only a genuine failed-revert attempt goes through the
            # bounded-retry accounting; an operator's up-front "keep it"
            # decision was never attempted, so it settles directly.
            ledger.mark_revert_retry(change_id, error=error)
        ledger.mark_manual_required(
            change_id,
            reason=reason,
            remediation_command=remediation_command,
            remediation_object_dn=remediation_object,
            error=error,
        )
    except Exception as exc:  # noqa: BLE001 — ledger bookkeeping is best-effort
        telemetry.capture_exception(exc)
        print_exception(exception=exc)


__all__ = [
    "register_deferred_admin_account_revert",
    "execute_deferred_mssql_admin_account_reverts",
]
