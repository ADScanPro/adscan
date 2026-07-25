"""Native LDAP query helpers for ADscan collectors.

This module is the preferred backend for plain LDAP filters that previously
shell-executed ``netexec ldap --query``. NetExec remains the right integration
for its protocol modules, but simple LDAP reads return structured data directly
via impacket so callers do not parse CLI output.
"""

from __future__ import annotations

from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConnection,
    LDAPEntry,
    execute_with_ldap_fallback,
)
from adscan_core.rich_output import print_exception


def domain_to_base_dn(domain: str) -> str:
    """Return the default naming context DN for a DNS domain."""
    labels = [part.strip() for part in str(domain or "").split(".") if part.strip()]
    return ",".join(f"DC={label}" for label in labels)


def _format_ldap_value(value: Any) -> str:
    """Convert a raw attribute value to a stable display string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            from winacl.dtyp.sid import SID  # type: ignore

            return str(SID.from_bytes(value))
        except Exception:  # noqa: BLE001
            return value.hex()
    return str(value).strip()


def _extract_attribute_values(entries: list[LDAPEntry], attribute: str) -> list[str]:
    """Extract one attribute from LDAPEntry list preserving query order."""
    values: list[str] = []
    attr_key = str(attribute or "").strip()
    if not attr_key:
        return values

    for entry in entries:
        mapping = entry.entry_attributes_as_dict
        raw_values: list[Any] | None = None
        for key, candidate in mapping.items():
            if str(key).casefold() == attr_key.casefold():
                raw_values = candidate
                break
        if raw_values is None:
            continue
        iterable = raw_values if isinstance(raw_values, (list, tuple, set)) else [raw_values]
        for raw_value in iterable:
            formatted = _format_ldap_value(raw_value)
            if formatted:
                values.append(formatted)
    return values


def query_ldap_attribute_values(
    *,
    operation_name: str,
    target_domain: str,
    dc_address: str,
    ldap_filter: str,
    attribute: str,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    prefer_ldaps: bool = True,
    kerberos_target_hostname: str | None = None,
    search_base: str | None = None,
    allow_password_fallback_on_kerberos_failure: bool = True,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
) -> tuple[list[str], bool]:
    """Execute one LDAP filter and return values for one requested attribute."""
    base_dn = str(search_base or "").strip() or domain_to_base_dn(target_domain)
    if not base_dn:
        raise ValueError(f"{operation_name} requires a search base or target domain.")

    def _collect(connection: ADscanLDAPConnection) -> list[str]:
        connection.search(
            search_base=base_dn,
            search_filter=ldap_filter,
            attributes=[attribute],
            search_scope="SUBTREE",
            paged_size=1000,
        )
        return _extract_attribute_values(connection.entries, attribute)

    values, used_ldaps = execute_with_ldap_fallback(
        operation_name=operation_name,
        target_domain=target_domain,
        dc_address=dc_address,
        callback=_collect,
        username=username,
        password=password,
        use_kerberos=use_kerberos,
        prefer_ldaps=prefer_ldaps,
        kerberos_target_hostname=kerberos_target_hostname,
        allow_password_fallback_on_kerberos_failure=allow_password_fallback_on_kerberos_failure,
        auth_domain=auth_domain,
        auth_kdc=auth_kdc,
    )
    return [str(v).strip() for v in values if str(v).strip()], used_ldaps


def query_shell_ldap_attribute_values(
    shell: Any,
    *,
    domain: str,
    ldap_filter: str,
    attribute: str,
    auth_username: str | None = None,
    auth_password: str | None = None,
    pdc: str | None = None,
    prefer_kerberos: bool = True,
    allow_ntlm_fallback: bool = True,
    operation_name: str = "LDAP query",
) -> list[str] | None:
    """Resolve shell context and execute a native LDAP attribute query."""
    from adscan_internal.services.ldap_transport_service import (
        bind_workspace_ticket_for_user,
        prepare_kerberos_ldap_environment,
        resolve_ldap_target_endpoints,
    )

    domains_data = getattr(shell, "domains_data", {})
    domain_data = domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
    if not isinstance(domain_data, dict):
        return None

    username = str(auth_username or domain_data.get("username") or "").strip()
    password = str(auth_password or domain_data.get("password") or "").strip()
    if not username or not password:
        return None

    auth_domain = str(getattr(shell, "domain", None) or domain)
    auth_domain_data = (
        domains_data.get(auth_domain, {}) if isinstance(domains_data, dict) else {}
    )
    if not isinstance(auth_domain_data, dict):
        auth_domain_data = {}
    auth_kdc = str(auth_domain_data.get("pdc") or "").strip() or None

    # Kerberos readiness is per-user, not per-domain.  Historically this code
    # treated any non-empty ``kerberos_tickets`` dict as proof that Kerberos
    # was ready, which produced an LDAP loop crash in workspaces that had
    # tickets for *other* users (e.g. RBCD-derived ccaches stored under
    # ``administrator``).  We now require a validated TGT for the active
    # ``username`` and bind it explicitly to the process before declaring
    # Kerberos ready.
    kerberos_ready = False
    if prefer_kerberos:
        kerberos_ready = bind_workspace_ticket_for_user(
            domains_data=domains_data,
            domain=domain,
            username=username,
            realm=auth_domain,
        )
        if not kerberos_ready:
            workspace_dir = str(
                getattr(shell, "current_workspace_dir", "")
                or getattr(shell, "_get_workspace_cwd", lambda: "")()
                or ""
            )
            kerberos_ready = prepare_kerberos_ldap_environment(
                operation_name=operation_name,
                target_domain=domain,
                workspace_dir=workspace_dir,
                username=username,
                user_domain=auth_domain,
                domains_data=domains_data,
                sync_clock=getattr(shell, "do_sync_clock_with_pdc", None),
            )

    endpoints = resolve_ldap_target_endpoints(
        target_domain=domain,
        domain_data={**domain_data, "pdc": pdc or domain_data.get("pdc")},
        kerberos_ready=kerberos_ready,
    )
    dc_address = str(pdc or endpoints.dc_address or "").strip()
    if not dc_address:
        return None

    marked_domain = mark_sensitive(domain, "domain")
    marked_dc = mark_sensitive(dc_address, "host")
    print_info_debug(
        f"[ldap-query] {operation_name} via native LDAP for {marked_domain} using {marked_dc}"
    )
    try:
        values, _used_ldaps = query_ldap_attribute_values(
            operation_name=operation_name,
            target_domain=domain,
            dc_address=dc_address,
            ldap_filter=ldap_filter,
            attribute=attribute,
            username=username,
            password=password,
            use_kerberos=kerberos_ready,
            prefer_ldaps=True,
            kerberos_target_hostname=endpoints.kerberos_target_hostname,
            allow_password_fallback_on_kerberos_failure=allow_ntlm_fallback,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_info_debug(
            f"[ldap-query] {operation_name} failed for {marked_domain}: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return None
    return values
