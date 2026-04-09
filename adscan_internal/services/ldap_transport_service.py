"""Shared LDAP transport helpers with LDAPS->LDAP fallback.

This module centralizes the transport policy for LDAP-backed domain collectors.
ADscan still relies heavily on CLI tooling, but for the smaller set of
domain-scope collectors implemented in Python we want a single place that
decides:

- how CertiHound-style LDAP connections are opened
- when an LDAPS failure should trigger an LDAP retry
- how those retries are logged consistently
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_warning_debug


class LDAPTransportValidationError(RuntimeError):
    """Raised when an LDAP connection opens but is not usable for queries."""


@dataclass(frozen=True)
class LDAPTargetEndpoints:
    """Resolved LDAP transport and Kerberos target endpoints for one domain."""

    dc_address: str | None
    kerberos_target_hostname: str | None
    dc_ip: str | None
    dc_fqdn: str | None


def _build_kerberos_aware_config_class(base_cls: type[Any]) -> type[Any]:
    """Return a config class that carries an explicit Kerberos target host."""

    class _KerberosAwareLDAPConfig(base_cls):  # type: ignore[misc,valid-type]
        kerberos_target_hostname: str | None = None

        def __init__(self, **kwargs: Any) -> None:
            kerberos_target_hostname = kwargs.pop("kerberos_target_hostname", None)
            super().__init__(**kwargs)
            self.kerberos_target_hostname = kerberos_target_hostname

    return _KerberosAwareLDAPConfig


def _build_kerberos_aware_connection_class(base_cls: type[Any]) -> type[Any]:
    """Return a connection class that forces the GSSAPI target hostname."""

    class _KerberosAwareLDAPConnection(base_cls):  # type: ignore[misc,valid-type]
        def _connect_kerberos(self) -> Any:
            from ldap3 import Connection, SASL  # type: ignore

            target_host = str(
                getattr(self.config, "kerberos_target_hostname", None)
                or self.config.server_address
            ).strip()
            return Connection(
                self._server,
                authentication=SASL,
                sasl_mechanism="GSSAPI",
                sasl_credentials=(target_host,),
                auto_bind=False,
            )

    return _KerberosAwareLDAPConnection


def resolve_ldap_target_endpoints(
    *,
    target_domain: str,
    domain_data: Mapping[str, Any] | None,
    kerberos_ready: bool,
) -> LDAPTargetEndpoints:
    """Resolve transport and Kerberos target endpoints for one domain.

    Args:
        target_domain: DNS domain name.
        domain_data: Domain metadata loaded in the shell workspace.
        kerberos_ready: Whether the caller intends to authenticate with Kerberos.

    Returns:
        Resolved transport target plus the FQDN that Kerberos should use for the
        service principal name.
    """

    dc_fqdn = None
    if isinstance(domain_data, Mapping):
        dc_fqdn = domain_data.get("pdc_hostname_fqdn") or domain_data.get("pdc_fqdn")
        if not dc_fqdn:
            pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
            if pdc_hostname:
                dc_fqdn = (
                    pdc_hostname
                    if "." in pdc_hostname
                    else f"{pdc_hostname}.{target_domain}"
                )
    dc_ip = (
        str(domain_data.get("pdc") or "").strip()
        if isinstance(domain_data, Mapping)
        else ""
    )
    kerberos_target_hostname = str(dc_fqdn or "").strip() or None
    _ = kerberos_ready
    dc_address = dc_ip or str(dc_fqdn or "").strip() or None
    return LDAPTargetEndpoints(
        dc_address=dc_address,
        kerberos_target_hostname=kerberos_target_hostname,
        dc_ip=dc_ip or None,
        dc_fqdn=str(dc_fqdn or "").strip() or None,
    )


def prepare_kerberos_ldap_environment(
    *,
    operation_name: str,
    target_domain: str,
    workspace_dir: str,
    username: str,
    user_domain: str,
    domains_data: Mapping[str, Any] | None = None,
    sync_clock: Callable[[str], Any] | None = None,
) -> bool:
    """Prepare Kerberos env vars and clock sync for LDAP-backed collectors.

    This is the canonical preflight for any Python LDAP workflow that wants to
    authenticate with Kerberos against a domain controller.

    Returns:
        ``True`` when a usable workspace Kerberos ticket was configured.
    """
    from adscan_internal import telemetry
    from adscan_internal.services import KerberosTicketService

    domain_key = str(target_domain or "").strip()
    workspace_root = str(workspace_dir or "").strip()
    user_name = str(username or "").strip()
    auth_domain = str(user_domain or domain_key).strip() or domain_key
    marked_operation = mark_sensitive(operation_name, "path")

    if not domain_key or not workspace_root:
        print_info_debug(
            f"[ldap] {marked_operation} missing workspace/domain context; Kerberos LDAP env setup skipped."
        )
        return False

    if sync_clock is not None:
        try:
            sync_clock(domain_key)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[ldap] Kerberos clock sync failed before {marked_operation} for "
                f"{mark_sensitive(domain_key, 'domain')}: {exc}"
            )

    try:
        krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path = (
            KerberosTicketService().setup_environment_for_domain(
                workspace_dir=workspace_root,
                domain=domain_key,
                user_domain=auth_domain,
                username=user_name or None,
                domains_data=domains_data,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ldap] Failed to prepare Kerberos LDAP environment for "
            f"{mark_sensitive(domain_key, 'domain')}: {exc}"
        )
        return False

    if krb5_config_set and krb5_config_path:
        print_info_debug(
            f"[ldap] Using workspace krb5.conf for {marked_operation}: "
            f"{mark_sensitive(krb5_config_path, 'path')}"
        )
    else:
        workspace_conf = Path(workspace_root).expanduser().resolve() / "krb5.conf"
        print_info_debug(
            f"[ldap] No workspace krb5.conf available for {marked_operation} at "
            f"{mark_sensitive(str(workspace_conf), 'path')}"
        )

    if kerberos_ticket_set and ticket_path and os.path.exists(ticket_path):
        print_info_debug(
            f"[ldap] Using workspace Kerberos ticket for {marked_operation}: "
            f"{mark_sensitive(ticket_path, 'path')}"
        )
        return True

    print_info_debug(
        f"[ldap] No workspace Kerberos ticket available for "
        f"{mark_sensitive(user_name, 'username')}@{mark_sensitive(auth_domain, 'domain')} "
        f"during {marked_operation}; falling back to password-backed LDAP bind."
    )
    return False


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Return the exception with its ``__cause__`` / ``__context__`` chain."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def is_ldaps_transport_failure(exc: BaseException) -> bool:
    """Return whether one exception looks like an LDAPS transport/TLS failure."""
    indicators = (
        "socket ssl wrapping error",
        "socket is not open",
        "ldapsocketopenerror",
        "ssl handshake error",
        "connection reset by peer",
        "unable to send message",
        "tls",
        "ldaps",
        "ldaptransportvalidationerror",
    )
    for candidate in _walk_exception_chain(exc):
        class_name = type(candidate).__name__.strip().lower()
        message = str(candidate or "").strip().lower()
        haystacks = (class_name, message)
        if any(indicator in haystack for haystack in haystacks for indicator in indicators):
            return True
    return False


def is_kerberos_auth_failure(exc: BaseException) -> bool:
    """Return whether one exception looks like a Kerberos/GSSAPI auth failure."""

    indicators = (
        "server not found in kerberos database",
        "ticket expired",
        "krb_ap_err",
        "kerberos",
        "gssapi",
        "gsserror",
        "preauthentication failed",
        "no credentials were supplied",
        "cannot find kdc",
        "client not found in kerberos database",
    )
    for candidate in _walk_exception_chain(exc):
        class_name = type(candidate).__name__.strip().lower()
        message = str(candidate or "").strip().lower()
        haystacks = (class_name, message)
        if any(indicator in haystack for haystack in haystacks for indicator in indicators):
            return True
    return False


def _validate_rootdse_query(connection: Any) -> None:
    """Ensure one LDAP connection can execute a minimal rootDSE query."""
    attempts = (
        ["namingContexts"],
        ["defaultNamingContext"],
        ["*"],
    )

    last_exc: BaseException | None = None
    for attributes in attempts:
        try:
            search_result = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                attributes=attributes,
                search_scope="BASE",
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue

        entries = getattr(getattr(connection, "connection", None), "entries", None)
        if isinstance(entries, list) and entries:
            return
        if isinstance(search_result, list) and search_result:
            return

    if last_exc is not None:
        raise LDAPTransportValidationError(
            "LDAP transport validation failed during rootDSE query"
        ) from last_exc
    raise LDAPTransportValidationError(
        "LDAP transport validation failed: rootDSE query returned no entries"
    )


def execute_with_ldap_fallback(
    *,
    operation_name: str,
    target_domain: str,
    dc_address: str,
    config_cls: type[Any],
    connection_cls: type[Any],
    callback: Callable[[Any], Any],
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    prefer_ldaps: bool = True,
    validate_connection: Callable[[Any], None] | None = None,
    config_overrides: Mapping[str, Any] | None = None,
    kerberos_target_hostname: str | None = None,
    allow_password_fallback_on_kerberos_failure: bool = False,
) -> tuple[Any, bool]:
    """Execute one LDAP-backed callback with centralized LDAPS->LDAP fallback.

    Returns:
        Tuple ``(result, used_ldaps)``.

    Raises:
        Exception: Re-raises the terminal connection/operation error.
    """
    attempts = [prefer_ldaps]
    if prefer_ldaps:
        attempts.append(False)

    marked_operation = mark_sensitive(operation_name, "path")
    marked_domain = mark_sensitive(target_domain, "domain")
    marked_dc = mark_sensitive(dc_address, "host")
    last_exc: Exception | None = None

    auth_attempts: list[bool] = [use_kerberos]
    can_retry_with_password = (
        use_kerberos
        and allow_password_fallback_on_kerberos_failure
        and bool(str(username or "").strip())
        and bool(str(password or "").strip())
    )
    if can_retry_with_password:
        auth_attempts.append(False)

    for use_kerberos_auth in auth_attempts:
        effective_config_cls = config_cls
        effective_connection_cls = connection_cls
        if use_kerberos_auth and str(kerberos_target_hostname or "").strip():
            effective_config_cls = _build_kerberos_aware_config_class(config_cls)
            effective_connection_cls = _build_kerberos_aware_connection_class(connection_cls)

        retry_with_password = False
        for use_ldaps in attempts:
            transport = "LDAPS" if use_ldaps else "LDAP"
            auth_mode = "Kerberos" if use_kerberos_auth else "password"
            print_info_debug(
                f"[ldap] Attempting {marked_operation} over {transport} for "
                f"{marked_domain} via {marked_dc} using {auth_mode} auth"
            )
            config_kwargs: dict[str, Any] = {
                "domain": target_domain,
                "dc_ip": dc_address,
                "use_ldaps": use_ldaps,
                "use_kerberos": use_kerberos_auth,
            }
            if isinstance(config_overrides, Mapping):
                config_kwargs.update(dict(config_overrides))
            if use_kerberos_auth and str(kerberos_target_hostname or "").strip():
                config_kwargs["kerberos_target_hostname"] = str(
                    kerberos_target_hostname
                ).strip()
            if not use_kerberos_auth:
                if not username or not password:
                    raise ValueError(
                        f"{operation_name} with password auth requires username and password."
                    )
                config_kwargs["username"] = username
                config_kwargs["password"] = password

            try:
                config = effective_config_cls(**config_kwargs)
                with effective_connection_cls(config) as connection:
                    validator = validate_connection or _validate_rootdse_query
                    validator(connection)
                    result = callback(connection)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if use_ldaps and prefer_ldaps and is_ldaps_transport_failure(exc):
                    print_warning_debug(
                        f"[ldap] {marked_operation} failed over LDAPS for {marked_domain}; "
                        "retrying over LDAP"
                    )
                    continue
                if (
                    use_kerberos_auth
                    and can_retry_with_password
                    and is_kerberos_auth_failure(exc)
                ):
                    print_warning_debug(
                        f"[ldap] {marked_operation} Kerberos auth failed for {marked_domain} "
                        f"via {marked_dc}; retrying with password bind"
                    )
                    retry_with_password = True
                    break
                raise

            if not use_ldaps:
                print_info_debug(
                    f"[ldap] LDAP fallback succeeded for {marked_operation} on {marked_domain}"
                )
            if not use_kerberos_auth and use_kerberos:
                print_info_debug(
                    f"[ldap] Password bind fallback succeeded for {marked_operation} on "
                    f"{marked_domain}"
                )
            return result, bool(use_ldaps)

        if retry_with_password:
            continue

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"{operation_name} failed without executing any LDAP attempt")
