"""Which administrator credential reads a host's patch level.

The patch-level CVE checks read ``CurrentBuildNumber`` / ``UBR`` over Remote
Registry. A default host answers that read for an administrator and refuses it
for an ordinary user, so the read is made with an administrator of the host
whenever ADscan holds one. The order follows the credential SSOTs:

1. **Domain-wide administrator** (Domain Admin, Enterprise Admin, the domain's
   RID 500), resolved once for the domain through
   :func:`~adscan_internal.services.credentials.pick_credential_for_local_admin`
   with no target host. It administers every member of the domain.
2. **An administrator of this host**: a domain account the attack graph proves
   is local administrator of the host (``AdminTo``), through the same picker
   with the host as target.
3. **The host's own local administrator material**: a local account stored for
   the host (LAPS, a SAM dump), the built-in Administrator first. It signs in
   as a LOCAL account (``is_local_account``), never against a domain controller.

A domain principal's secret is pre-minted into ONE ticket through
:func:`~adscan_internal.services.sweep_credential.resolve_sweep_credential`
(memoized per principal), so a fleet read sends the secret once, not once per
host, and a rejected secret aborts that principal for the run instead of being
sprayed. Every sign-in still passes the transport-seam lockout guard
(``adscan_core.auth_attempt_guard``).

The resolver is synchronous (graph reads, ticket minting); the cache runs it off
the event loop.
"""

from __future__ import annotations

from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.host_patch_level import AccessResolver, HostAccess

SOURCE_DOMAIN_ADMIN = "domain_admin"
SOURCE_LOCAL_ADMIN_VERIFIED = "local_admin_verified"
SOURCE_LOCAL_ACCOUNT = "local_account"

_BUILTIN_ADMINISTRATOR = "administrator"


def build_host_admin_access_resolver(
    shell: Any,
    *,
    domain: str,
    dc_ip: str | None,
) -> AccessResolver | None:
    """Return the resolver the patch-level cache calls per host, or ``None``.

    ``None`` without a shell or a domain: the checks then read with the scan
    credential only, exactly as before.
    """
    if shell is None or not domain:
        return None
    state: dict[str, Any] = {"domain_admin": None, "domain_admin_resolved": False, "minted": {}}

    def _resolve(host: str, target_hostname: str | None) -> HostAccess | None:
        try:
            return _resolve_for_host(
                shell, domain=domain, dc_ip=dc_ip, host=host, target_hostname=target_hostname, state=state
            )
        except Exception as exc:  # noqa: BLE001 - no access means the standard read
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            return None

    return _resolve


def _resolve_for_host(
    shell: Any,
    *,
    domain: str,
    dc_ip: str | None,
    host: str,
    target_hostname: str | None,
    state: dict[str, Any],
) -> HostAccess | None:
    from adscan_internal.services.credentials import (  # noqa: PLC0415
        pick_credential_for_local_admin,
    )

    # 1. Domain-wide administrator, once for the domain.
    if not state["domain_admin_resolved"]:
        state["domain_admin_resolved"] = True
        state["domain_admin"] = pick_credential_for_local_admin(shell, domain=domain, target_host=None)
    picked = state["domain_admin"]
    source = SOURCE_DOMAIN_ADMIN
    # 2. A domain account proven to administer this host.
    if picked is None:
        for candidate in (target_hostname, host):
            if candidate:
                picked = pick_credential_for_local_admin(shell, domain=domain, target_host=candidate)
                if picked is not None:
                    source = SOURCE_LOCAL_ADMIN_VERIFIED
                    break
    if picked is not None:
        username, secret, kind = picked
        config = _domain_principal_config(
            shell,
            domain=domain,
            dc_ip=dc_ip,
            host=host,
            target_hostname=target_hostname,
            username=username,
            secret=secret,
            kind=kind,
            minted=state["minted"],
        )
        if config is not None:
            print_info_debug(
                f"[patch-level] {mark_sensitive(host, 'host')}: administrative read as "
                f"{mark_sensitive(username, 'user')} ({source})"
            )
            return HostAccess(config=config, principal=username, source=source)
    # 3. The host's own local administrator material.
    return _local_account_access(shell, domain=domain, host=host, target_hostname=target_hostname)


def _domain_principal_config(
    shell: Any,
    *,
    domain: str,
    dc_ip: str | None,
    host: str,
    target_hostname: str | None,
    username: str,
    secret: str,
    kind: Any,
    minted: dict[str, Any],
) -> Any | None:
    """An ``SMBConfig`` for a domain principal, its ticket minted once per run."""
    from adscan_internal.services.credentials import CredentialKind  # noqa: PLC0415

    key = username.strip().lower()
    if key not in minted:
        from adscan_internal.services.sweep_credential import (  # noqa: PLC0415
            resolve_sweep_credential,
        )

        kwargs: dict[str, Any] = {}
        if kind is CredentialKind.PASSWORD:
            kwargs["password"] = secret
        elif kind is CredentialKind.NT_HASH:
            kwargs["nt_hash"] = secret
        elif kind in (CredentialKind.AES256_KEY, CredentialKind.AES128_KEY):
            kwargs["aes_key"] = secret
        elif kind is CredentialKind.CCACHE_PATH:
            kwargs["ccache_path"] = secret
        sweep = resolve_sweep_credential(
            shell, domain=domain, username=username, kdc_ip=dc_ip, **kwargs
        )
        if sweep.aborted:
            print_info_debug(
                f"[patch-level] no administrative read as {mark_sensitive(username, 'user')}: "
                f"{sweep.abort_reason or 'ticket pre-mint failed'}"
            )
        minted[key] = None if sweep.aborted else sweep
    sweep = minted[key]
    if sweep is None:
        return None
    from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

    # The minted ticket leads (Kerberos first). The password / hash the mint
    # just proved stays as the posture-pruned NTLM leg, the same shape as the
    # CA-host reads (``resolve_esc12_credential``): a host known only by IP has
    # no FQDN for a ``cifs/`` SPN, and NTLM is then the only way in.
    return SMBConfig(
        target_ip=host,
        target_hostname=target_hostname or host,
        domain=domain,
        auth_domain=domain,
        username=username,
        password=sweep.password or (secret if kind is CredentialKind.PASSWORD else None),
        nt_hash=sweep.nt_hash or (secret if kind is CredentialKind.NT_HASH else None),
        aes_key=sweep.aes_key,
        ccache_path=sweep.ccache_path,
        kdc_ip=dc_ip,
        use_kerberos=bool(sweep.use_kerberos),
        posture_snapshot=_posture(shell, domain),
    )


def _local_account_access(
    shell: Any, *, domain: str, host: str, target_hostname: str | None
) -> HostAccess | None:
    """A stored local account of this host (LAPS / SAM), built-in Administrator first."""
    from adscan_internal.services.credential_store_service import (  # noqa: PLC0415
        expand_host_query_aliases,
        hosts_match,
        iter_local_credential_records,
    )

    aliases: set[str] = set()
    for candidate in (host, target_hostname):
        if candidate:
            aliases |= expand_host_query_aliases(shell, domain=domain, host=candidate)
    if not aliases:
        return None
    records = [
        r
        for r in iter_local_credential_records(getattr(shell, "domains_data", None), domain=domain)
        if r.service.lower() == "smb" and any(hosts_match(r.host, a) for a in aliases)
    ]
    if not records:
        return None
    records.sort(key=lambda r: 0 if r.username.strip().lower() == _BUILTIN_ADMINISTRATOR else 1)
    record = records[0]

    from adscan_internal.services.credential_store_service import looks_like_ntlm_hash  # noqa: PLC0415
    from adscan_internal.services.smb_privilege import local_account_logon_domain  # noqa: PLC0415
    from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

    is_hash = looks_like_ntlm_hash(record.secret)
    config = SMBConfig(
        target_ip=host,
        target_hostname=target_hostname or host,
        domain=domain,
        auth_domain=local_account_logon_domain(target_hostname or record.host or host),
        username=record.username,
        password=None if is_hash else record.secret,
        nt_hash=record.secret if is_hash else None,
        is_local_account=True,
        posture_snapshot=_posture(shell, domain),
    )
    print_info_debug(
        f"[patch-level] {mark_sensitive(host, 'host')}: administrative read as the local "
        f"account {mark_sensitive(record.username, 'user')}"
    )
    return HostAccess(config=config, principal=f"{record.host}\\{record.username}", source=SOURCE_LOCAL_ACCOUNT)


def _posture(shell: Any, domain: str) -> Any | None:
    try:
        from adscan_internal.services.domain_posture import get_posture  # noqa: PLC0415

        return get_posture(getattr(shell, "domains_data", {}) or {}, domain=domain)
    except Exception:  # noqa: BLE001 - posture is advisory
        return None


__all__ = [
    "SOURCE_DOMAIN_ADMIN",
    "SOURCE_LOCAL_ACCOUNT",
    "SOURCE_LOCAL_ADMIN_VERIFIED",
    "build_host_admin_access_resolver",
]
