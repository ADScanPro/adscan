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
from pathlib import Path
from typing import Any

from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_warning_debug


class LDAPTransportValidationError(RuntimeError):
    """Raised when an LDAP connection opens but is not usable for queries."""


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

    last_exc: Exception | None = None
    final_result: Any | None = None
    final_used_ldaps: bool | None = None
    for use_ldaps in attempts:
        transport = "LDAPS" if use_ldaps else "LDAP"
        marked_operation = mark_sensitive(operation_name, "path")
        marked_domain = mark_sensitive(target_domain, "domain")
        marked_dc = mark_sensitive(dc_address, "host")
        print_info_debug(
            f"[ldap] Attempting {marked_operation} over {transport} for "
            f"{marked_domain} via {marked_dc}"
        )
        config_kwargs: dict[str, Any] = {
            "domain": target_domain,
            "dc_ip": dc_address,
            "use_ldaps": use_ldaps,
            "use_kerberos": use_kerberos,
        }
        if not use_kerberos:
            if not username or not password:
                raise ValueError(
                    f"{operation_name} with password auth requires username and password."
                )
            config_kwargs["username"] = username
            config_kwargs["password"] = password

        try:
            config = config_cls(**config_kwargs)
            with connection_cls(config) as connection:
                validator = validate_connection or _validate_rootdse_query
                validator(connection)
                final_result = callback(connection)
                final_used_ldaps = use_ldaps
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if use_ldaps and prefer_ldaps and is_ldaps_transport_failure(exc):
                print_warning_debug(
                    f"[ldap] {marked_operation} failed over LDAPS for {marked_domain}; "
                    "retrying over LDAP"
                )
                continue
            raise
        if not use_ldaps:
            print_info_debug(
                f"[ldap] LDAP fallback succeeded for {marked_operation} on {marked_domain}"
            )
        return final_result, bool(final_used_ldaps)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError(f"{operation_name} failed without executing any LDAP attempt")
