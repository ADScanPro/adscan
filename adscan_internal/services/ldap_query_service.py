"""Native LDAP query helpers for ADscan collectors.

This module is the preferred backend for plain LDAP filters that previously
shell-executed ``netexec ldap --query``. NetExec remains the right integration
for its protocol modules, but simple LDAP reads should return structured data
directly from ldap3 so callers do not parse CLI output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.ldap_transport_service import execute_with_ldap_fallback


@dataclass
class NativeLDAPQueryConfig:
    """Minimal LDAP connection config compatible with ADscan fallback policy."""

    domain: str
    dc_ip: str
    use_ldaps: bool
    use_kerberos: bool
    username: str | None = None
    password: str | None = None
    kerberos_target_hostname: str | None = None


class NativeLDAPQueryConnection:
    """Small ldap3-backed context manager for generic LDAP searches."""

    def __init__(self, config: NativeLDAPQueryConfig) -> None:
        self.config = config
        self.connection: Any | None = None
        self._server: Any | None = None

    def __enter__(self) -> "NativeLDAPQueryConnection":
        from ldap3 import Server

        self._server = Server(
            self.config.dc_ip,
            use_ssl=bool(self.config.use_ldaps),
            connect_timeout=10,
        )
        self.connection = (
            self._connect_kerberos()
            if bool(self.config.use_kerberos)
            else self._connect_password()
        )
        if not bool(getattr(self.connection, "bound", False)):
            self.connection.bind()
        return self

    def __exit__(self, *_args: Any) -> None:
        if self.connection is not None:
            self.connection.unbind()

    def _connect_kerberos(self) -> Any:
        from ldap3 import Connection, SASL

        target_host = str(
            self.config.kerberos_target_hostname or self.config.dc_ip
        ).strip()
        return Connection(
            self._server,
            authentication=SASL,
            sasl_mechanism="GSSAPI",
            sasl_credentials=(target_host,),
            auto_bind=False,
            receive_timeout=30,
        )

    def _connect_password(self) -> Any:
        from ldap3 import Connection, NTLM

        username = str(self.config.username or "").strip()
        if "\\" not in username and "@" not in username:
            username = f"{self.config.domain}\\{username}"
        return Connection(
            self._server,
            user=username,
            password=str(self.config.password or ""),
            authentication=NTLM,
            auto_bind=False,
            receive_timeout=30,
        )

    def search(self, *args: Any, **kwargs: Any) -> Any:
        """Proxy ldap3 search calls while preserving ``connection.entries``."""
        if self.connection is None:
            raise RuntimeError("LDAP connection is not open")
        return self.connection.search(*args, **kwargs)


def domain_to_base_dn(domain: str) -> str:
    """Return the default naming context DN for a DNS domain."""
    labels = [part.strip() for part in str(domain or "").split(".") if part.strip()]
    return ",".join(f"DC={label}" for label in labels)


def _format_ldap_value(value: Any) -> str:
    """Convert ldap3 attribute values to stable display strings."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            from impacket.ldap.ldaptypes import LDAP_SID

            sid = LDAP_SID(value)
            return sid.formatCanonical()
        except Exception:
            return value.hex()
    return str(value).strip()


def _extract_attribute_values(entries: list[Any], attribute: str) -> list[str]:
    """Extract one attribute from ldap3 entries preserving query order."""
    values: list[str] = []
    attr_key = str(attribute or "").strip()
    if not attr_key:
        return values

    for entry in entries:
        attributes = getattr(entry, "entry_attributes_as_dict", None)
        if callable(attributes):
            raw_mapping = attributes
        else:
            raw_mapping = getattr(entry, "entry_attributes_as_dict", {})
        mapping = raw_mapping if isinstance(raw_mapping, dict) else {}
        raw_values = None
        for key, candidate in mapping.items():
            if str(key).casefold() == attr_key.casefold():
                raw_values = candidate
                break
        if raw_values is None and hasattr(entry, attr_key):
            raw_values = getattr(entry, attr_key)

        if raw_values is None:
            continue
        if isinstance(raw_values, (list, tuple, set)):
            iterable = raw_values
        else:
            iterable = [raw_values]
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
) -> tuple[list[str], bool]:
    """Execute one LDAP filter and return values for one requested attribute."""
    from ldap3 import SUBTREE

    base_dn = str(search_base or "").strip() or domain_to_base_dn(target_domain)
    if not base_dn:
        raise ValueError(f"{operation_name} requires a search base or target domain.")

    def _collect(connection: NativeLDAPQueryConnection) -> list[str]:
        connection.search(
            search_base=base_dn,
            search_filter=ldap_filter,
            attributes=[attribute],
            search_scope=SUBTREE,
            paged_size=1000,
        )
        entries = getattr(getattr(connection, "connection", None), "entries", None)
        if not isinstance(entries, list):
            entries = []
        return _extract_attribute_values(entries, attribute)

    values, used_ldaps = execute_with_ldap_fallback(
        operation_name=operation_name,
        target_domain=target_domain,
        dc_address=dc_address,
        config_cls=NativeLDAPQueryConfig,
        connection_cls=NativeLDAPQueryConnection,
        callback=_collect,
        username=username,
        password=password,
        use_kerberos=use_kerberos,
        prefer_ldaps=prefer_ldaps,
        kerberos_target_hostname=kerberos_target_hostname,
        allow_password_fallback_on_kerberos_failure=allow_password_fallback_on_kerberos_failure,
    )
    return [str(value).strip() for value in values if str(value).strip()], used_ldaps


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

    kerberos_ready = bool(prefer_kerberos and domain_data.get("kerberos_tickets"))
    if prefer_kerberos and not kerberos_ready:
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
            user_domain=str(getattr(shell, "domain", None) or domain),
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
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ldap-query] {operation_name} failed for {marked_domain}: "
            f"{mark_sensitive(str(exc), 'detail')}"
        )
        return None
    return values
