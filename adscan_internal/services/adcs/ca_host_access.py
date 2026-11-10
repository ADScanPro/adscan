"""Credentialed SMB access to a CA host, shared by every CA-host registry read.

Two readers need an authenticated Remote Registry session on a certification
authority's host: the ESC12 check and the CA registry probe that feeds ESC6,
ESC11 and Certighost. Both go through ONE credential resolver so the rules
cannot drift.

Credential decision (verified against the protocol, not assumed)
----------------------------------------------------------------
Every one of those reads goes over MS-RRP (the ``\\winreg`` pipe) to
``HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\<CA>``
(``EditFlags``, ``InterfaceFlags``) and ``HKLM\\SOFTWARE\\Microsoft\\Windows NT\\
CurrentVersion`` (build / UBR). On a Windows Server the ``winreg`` pipe is
restricted by default to Administrators and Backup Operators
(``SecurePipeServers\\winreg``), so an ordinary authenticated user can only ever
obtain an access-denied answer. The builder therefore returns a configuration
ONLY for a credential PROVEN to administer the CA host (the credential SSOT
:func:`~adscan_internal.services.credentials.pick_credential_for_local_admin`),
never the low-privilege scan credential: a weaker one would add failed
authentications against the CA host for no information.

Proof of administration comes from two places, in order of availability.
During the collection itself the attack graph does not exist yet, so the caller
passes ``directory_roles``: the Domain Admin / Enterprise Admin /
BUILTIN\\Administrators / RID 500 roles it derived from the directory
membership it has just read (``privilege_role.directory_admin_roles``). That is
what lets a scan that STARTS as a Domain Admin read the CA registry on its first
pass. Once the collection is persisted, the picker resolves roles from the graph
as well, including a local administrator of the CA host found by the SMB sweep;
the collection orchestrator re-runs the probe at that point for any CA the
first pass could not read (``ca_registry_rerun``).

When no such credential exists the builder returns ``None`` and the caller
records the checks as NOT ASSESSED.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception

CaHostSmbConfigBuilder = Callable[[str], Awaitable[Any]]


def resolve_ca_connect_and_spn(
    shell: Any, *, domain: str, dc_ip: str | None, ca_host: str
) -> tuple[str, str]:
    """Split a CA FQDN into ``(connect_ip, spn_fqdn)`` via the reachable-IP SSOT.

    Best-effort: with no shell, an IP host or any failure it returns
    ``(ca_host, ca_host)``. The IP is for the CONNECT, the FQDN stays the
    Kerberos SPN (an IP handed to Kerberos as the SPN would fail auth).
    """
    from adscan_internal.services._kerberos_spn import is_ip_address  # noqa: PLC0415

    if shell is None or not ca_host or is_ip_address(ca_host):
        return ca_host, ca_host
    try:
        from adscan_internal.services.host_address_resolver import (  # noqa: PLC0415
            resolve_connect_and_spn,
        )

        connect_ip, spn_fqdn = resolve_connect_and_spn(
            shell,
            host=ca_host,
            domain=domain,
            resolver_ip=str(dc_ip) if dc_ip else None,
            spn_hostname=ca_host,
        )
        return str(connect_ip), str(spn_fqdn)
    except Exception as exc:  # noqa: BLE001 - best-effort; keep the FQDN
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return ca_host, ca_host


def ca_host_smb_realms(
    *,
    host_domain: str | None,
    credential_domain: str | None,
    auth_kdc: str | None,
    target_kdc: str | None,
) -> dict[str, Any]:
    """The realm fields of an ``SMBConfig`` that authenticates to a CA host.

    Two axes, never collapsed (CLAUDE.md, auth vs target domain): the
    credential's own domain (``auth_domain``, whose KDC mints the TGT) and the
    domain that owns the CA host (``domain``, whose DC issues the service
    ticket after the cross-realm referral). When they differ the SMB transport
    follows the referral (``dcc`` / ``realmc``); when they were both set to the
    credential domain, the credential's KDC was asked for the CA host's ticket
    and returned the referral TGT itself, which the CA host rejected as
    ``STATUS_WRONG_PASSWORD``.
    """
    credential = str(credential_domain or host_domain or "").strip()
    host = str(host_domain or credential).strip()
    cross_realm = bool(host and credential and host.casefold() != credential.casefold())
    return {
        "domain": host or None,
        "auth_domain": credential or None,
        "kdc_ip": str(auth_kdc).strip() if auth_kdc else None,
        "target_kdc_ip": (str(target_kdc).strip() if target_kdc else None)
        if cross_realm
        else None,
    }


def collected_directory_roles(shell: Any, *, domain: str, result: Any) -> dict[str, Any]:
    """Return the administrative roles of stored credentials from a collection.

    Reads the accounts and ``MemberOf`` edges already in ``result`` (a
    ``CollectionResult``) and classifies ONLY the accounts that have a stored
    credential for ``domain``, through ``privilege_role.directory_admin_roles``.
    Empty when there is no shell, no stored credential or nothing qualifies.
    Never raises: a failure here only means the graph has to resolve the role
    later.
    """
    if shell is None or result is None:
        return {}
    try:
        from adscan_internal.services.credentials.privilege_role import (  # noqa: PLC0415
            DirectoryPrincipal,
            directory_admin_roles,
        )

        domains_data = getattr(shell, "domains_data", None) or {}
        domain_data = domains_data.get(domain) if isinstance(domains_data, dict) else None
        credentials = (domain_data or {}).get("credentials") if isinstance(domain_data, dict) else None
        if not isinstance(credentials, dict) or not credentials:
            return {}
        stored = {str(user or "").strip().lower() for user in credentials}
        principals = []
        for node in getattr(result, "nodes", {}).values():
            if getattr(node, "kind", "") != "User":
                continue
            sam = str(getattr(node, "samaccountname", "") or "").strip()
            if not sam or sam.lower() not in stored:
                continue
            props = getattr(node, "properties", None) or {}
            primary_group = props.get("primarygroupid") if isinstance(props, dict) else None
            principals.append(
                DirectoryPrincipal(
                    samaccountname=sam,
                    sid=str(getattr(node, "object_id", "") or ""),
                    enabled=getattr(node, "enabled", None),
                    primary_group_id=primary_group if isinstance(primary_group, int) else None,
                )
            )
        if not principals:
            return {}
        member_of = [
            (edge.source_object_id, edge.target_object_id)
            for edge in getattr(result, "edges", ())
            if getattr(edge, "relation", "") == "MemberOf"
        ]
        roles = directory_admin_roles(principals, member_of)
        if roles:
            from adscan_core.rich_output import print_info_debug  # noqa: PLC0415
            from adscan_internal.rich_output import mark_sensitive  # noqa: PLC0415

            print_info_debug(
                "[adcs-ca-access] collected directory membership qualifies "
                f"{len(roles)} stored credential(s) as CA-host administrator: "
                + ", ".join(
                    f"{mark_sensitive(user, 'user')}={role.value}"
                    for user, role in sorted(roles.items())
                )
            )
        return roles
    except Exception as exc:  # noqa: BLE001 - the graph resolves it later
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        return {}


def build_ca_host_smb_config_builder(
    shell: Any,
    *,
    domain: str,
    dc_ip: str | None,
    directory_roles: Mapping[str, Any] | None = None,
) -> CaHostSmbConfigBuilder | None:
    """Return the ``smb_config_builder`` the ADCS collector needs, or ``None``.

    ``None`` when there is no shell (nothing to resolve a credential from): the
    collector then records the registry-derived checks as not assessed.
    ``directory_roles`` is forwarded to the credential picker (see the module
    docstring).
    """
    if shell is None:
        return None

    async def _builder(ca_host: str) -> Any:
        from adscan_internal.services.adcs.esc12_detection import (  # noqa: PLC0415
            resolve_esc12_credential,
        )
        from adscan_internal.services.async_bridge import run_sync_off_loop  # noqa: PLC0415
        from adscan_internal.services.engagement_scope import (  # noqa: PLC0415
            collection_host_verdict,
        )

        # The collection of ``domain`` contacts only hosts ``domain`` owns (the
        # engagement-scope SSOT). The collector gates first; this keeps the
        # orchestrator re-run behind the same rule.
        verdict = collection_host_verdict(shell, host=ca_host, collecting_domain=domain)
        if not verdict.allowed:
            from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

            print_info_debug(
                f"[adcs-ca-access] CA host not contacted from this domain ({verdict.reason})"
            )
            return None

        connect_ip, spn_fqdn = run_sync_off_loop(
            resolve_ca_connect_and_spn, shell, domain=domain, dc_ip=dc_ip, ca_host=ca_host
        )
        credential = run_sync_off_loop(
            resolve_esc12_credential,
            shell,
            domain=domain,
            ca_host=ca_host,
            connect_ip=connect_ip,
            spn_fqdn=spn_fqdn,
            kdc_ip=str(dc_ip) if dc_ip else None,
            directory_roles=directory_roles,
            host_domain=domain,
        )
        return credential.smb_config if credential is not None else None

    return _builder


__all__ = [
    "CaHostSmbConfigBuilder",
    "build_ca_host_smb_config_builder",
    "ca_host_smb_realms",
    "collected_directory_roles",
    "resolve_ca_connect_and_spn",
]
