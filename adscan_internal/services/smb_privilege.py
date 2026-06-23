"""Native SMB administrative privilege checker — built on aiosmb via smb_transport.

Replaces the netexec "(Pwn3d!)" detection with a direct async SMB tree-connect
probe. Works in all environments:

  - NTLM available        → tries NTLM first, falls back to Kerberos on block
  - NTLM disabled by GPO  → goes straight to Kerberos (smb_machine_with_fallback)
  - SMB signing required  → smb_transport negotiates signing transparently
  - AES-only KDC          → kerberos_transport handles ETYPE-INFO2 probe
  - Cross-domain creds    → auth_domain / kdc_ip separate from target host

Admin detection method:
  1. Authenticate via smb_machine_with_fallback (NTLM → Kerberos auto-retry)
  2. tree_connect to \\\\host\\ADMIN$  — standard Windows admin share
  3. If ADMIN$ fails with ACCESS_DENIED, try C$ as fallback confirmation
  4. Any successful tree_connect → local admin confirmed
  5. AUTH failure  → credential error (not an admin check result)
  6. Network error → host unreachable / port closed
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Optional, Sequence

from adscan_internal import telemetry
from adscan_internal.rich_output import print_info_debug
from adscan_internal.services.posture_sink import PostureSink
from adscan_internal.services.smb_transport import (
    SMBAuthError,
    SMBConfig,
    SMBConnectionError,
    smb_machine_with_fallback,
)

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.domain_posture import DomainPosture


class SMBPrivilegeStatus(str, Enum):
    ADMIN = "admin"             # tree_connect to ADMIN$/C$ succeeded
    NOT_ADMIN = "not_admin"     # authenticated but ACCESS_DENIED on admin shares
    AUTH_FAILED = "auth_failed" # credentials rejected
    UNREACHABLE = "unreachable" # network / port / host error
    ERROR = "error"             # unexpected exception


@dataclass(frozen=True)
class SMBPrivilegeConfig:
    """Parameters for a single SMB privilege check.

    target_ip:       IP of the host to check.
    target_hostname: Optional hostname for Kerberos SPN (cifs/<hostname>).
    domain:          Domain of the target machine.
    username:        Account to test.
    password:        Plaintext password (mutually exclusive with nt_hash/aes_key/ccache_path).
    nt_hash:         NT hash for pass-the-hash (32 hex chars or LM:NT format).
    aes_key:         AES-128 (32 hex) or AES-256 (64 hex) key.
    ccache_path:     Path to Kerberos ccache file.
    auth_domain:     Credential domain when different from target domain (cross-domain).
    kdc_ip:          KDC for auth_domain (required for Kerberos in cross-domain scenarios).
    use_kerberos:    Force Kerberos; skip NTLM entirely.
    timeout:         Per-host connection timeout in seconds.
    posture_sink:    Optional sink for Intelligence Updates emitted by the
                     transport when it observes a domain-wide hardening signal.
    posture_snapshot: Optional posture snapshot threaded into the ``SMBConfig``
                     so the planner prunes impossible auth combinations.
    """
    target_ip: str
    domain: str
    username: str
    target_hostname: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    ccache_path: str | None = None
    auth_domain: str | None = None
    kdc_ip: str | None = None
    use_kerberos: bool = False
    timeout: int = 15
    posture_sink: Optional[PostureSink] = None
    posture_snapshot: Optional["DomainPosture"] = None

    def __post_init__(self) -> None:
        # Auto-route an NT hash that landed in the password field. See
        # services/credential_routing.py for the rationale.
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        new_pwd, new_hash, new_aes, new_cc = promote_credential_fields(
            password=self.password,
            nt_hash=self.nt_hash,
            aes_key=self.aes_key,
            ccache_path=self.ccache_path,
        )
        if new_pwd != self.password:
            object.__setattr__(self, "password", new_pwd)
        if new_hash != self.nt_hash:
            object.__setattr__(self, "nt_hash", new_hash)
        if new_aes != self.aes_key:
            object.__setattr__(self, "aes_key", new_aes)
        if new_cc != self.ccache_path:
            object.__setattr__(self, "ccache_path", new_cc)


@dataclass(frozen=True)
class SMBPrivilegeResult:
    """Result of one SMB privilege check against a single host."""
    target_ip: str
    target_hostname: str | None
    username: str
    domain: str
    status: SMBPrivilegeStatus
    admin_share: str | None = None   # "ADMIN$" or "C$" — which share confirmed admin
    auth_protocol: str | None = None # "NTLM" or "Kerberos"
    error: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.status == SMBPrivilegeStatus.ADMIN

    @property
    def auth_succeeded(self) -> bool:
        return self.status in (SMBPrivilegeStatus.ADMIN, SMBPrivilegeStatus.NOT_ADMIN)

    @property
    def display_host(self) -> str:
        return self.target_hostname or self.target_ip


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------

_ADMIN_SHARES = ("ADMIN$", "C$")


async def check_smb_privilege(config: SMBPrivilegeConfig) -> SMBPrivilegeResult:
    """Check if the given credentials have SMB admin access on the target host.

    Probes ADMIN$ first, then C$ as fallback. Any successful tree_connect
    confirms local administrator privileges.

    Constraints handled transparently:
    - NTLM disabled  → auto-retried with Kerberos via smb_machine_with_fallback
    - SMB signing    → negotiated by smb_transport
    - AES-only KDC   → handled by kerberos_transport ETYPE-INFO2 probe
    - Cross-domain   → auth_domain / kdc_ip plumbed through SMBConfig
    """
    smb_cfg = SMBConfig(
        target_ip=config.target_ip,
        target_hostname=config.target_hostname,
        domain=config.domain,
        username=config.username,
        password=config.password,
        nt_hash=config.nt_hash,
        aes_key=config.aes_key,
        ccache_path=config.ccache_path,
        auth_domain=config.auth_domain,
        kdc_ip=config.kdc_ip,
        use_kerberos=config.use_kerberos,
        timeout=config.timeout,
        posture_sink=config.posture_sink,
        posture_snapshot=config.posture_snapshot,
    )

    host_label = config.target_hostname or config.target_ip

    try:
        async with smb_machine_with_fallback(smb_cfg) as machine:
            conn = machine.connection

            # Detect which auth protocol was used
            auth_proto = _detect_auth_protocol(conn)

            # Probe admin shares in order
            for share in _ADMIN_SHARES:
                unc = f"\\\\{host_label}\\{share}"
                tree, err = await conn.tree_connect(unc)
                if err is None and tree is not None:
                    print_info_debug(
                        f"[smb_privilege] {config.username}@{host_label}: "
                        f"{share} tree_connect OK → admin confirmed"
                    )
                    return SMBPrivilegeResult(
                        target_ip=config.target_ip,
                        target_hostname=config.target_hostname,
                        username=config.username,
                        domain=config.domain,
                        status=SMBPrivilegeStatus.ADMIN,
                        admin_share=share,
                        auth_protocol=auth_proto,
                    )

                err_str = str(err).upper() if err else ""
                print_info_debug(
                    f"[smb_privilege] {config.username}@{host_label}: "
                    f"{share} → {err_str[:60]}"
                )
                # If it's not ACCESS_DENIED, stop trying more shares
                if err and "ACCESS_DENIED" not in err_str and "STATUS_ACCESS" not in err_str:
                    break

            return SMBPrivilegeResult(
                target_ip=config.target_ip,
                target_hostname=config.target_hostname,
                username=config.username,
                domain=config.domain,
                status=SMBPrivilegeStatus.NOT_ADMIN,
                auth_protocol=auth_proto,
            )

    except SMBAuthError as exc:
        print_info_debug(
            f"[smb_privilege] {config.username}@{host_label}: auth failed — {exc}"
        )
        return SMBPrivilegeResult(
            target_ip=config.target_ip,
            target_hostname=config.target_hostname,
            username=config.username,
            domain=config.domain,
            status=SMBPrivilegeStatus.AUTH_FAILED,
            error=str(exc),
        )

    except (SMBConnectionError, OSError, TimeoutError, asyncio.TimeoutError) as exc:
        print_info_debug(
            f"[smb_privilege] {config.username}@{host_label}: unreachable — {exc}"
        )
        return SMBPrivilegeResult(
            target_ip=config.target_ip,
            target_hostname=config.target_hostname,
            username=config.username,
            domain=config.domain,
            status=SMBPrivilegeStatus.UNREACHABLE,
            error=str(exc),
        )

    except Exception as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[smb_privilege] {config.username}@{host_label}: unexpected error — {exc}"
        )
        return SMBPrivilegeResult(
            target_ip=config.target_ip,
            target_hostname=config.target_hostname,
            username=config.username,
            domain=config.domain,
            status=SMBPrivilegeStatus.ERROR,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Batch check — concurrent, bounded parallelism
# ---------------------------------------------------------------------------

async def check_smb_privilege_batch(
    configs: Sequence[SMBPrivilegeConfig],
    *,
    max_concurrency: int = 10,
    per_host_budget: float | None = None,
) -> list[SMBPrivilegeResult]:
    """Run multiple SMB privilege checks concurrently with bounded parallelism.

    Returns results in the same order as configs.
    max_concurrency controls simultaneous SMB connections (default 10).

    ``per_host_budget`` is a wall-clock bound (seconds) on the WHOLE per-host
    probe — connect + Kerberos pre-mint + the ADMIN$/C$ tree_connects — NOT just
    the aiosmb connection timeout. A host that TCP-accepts 445 but then hangs the
    SMB negotiate or Kerberos (a host stale-dead since the port scan, or a kerbad
    AP_REP parse error) is recorded UNREACHABLE instead of blocking the gather
    indefinitely (the >10min stall this fixes). ``None`` derives it per-config
    from the connection timeout.
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    # Per-host probe timings (host, elapsed_s, status) — debug-only diagnostics so
    # we can see WHICH host makes the sweep feel "stuck at the end" (the gather
    # waits for the slowest probe). Zero cost in non-debug runs (print_info_debug
    # is a no-op). The collector has the same per-phase timing discipline.
    timings: list[tuple[str, float, str]] = []
    #: A probe slower than this is called out individually at debug level.
    slow_host_threshold_s = 8.0

    async def _bounded(cfg: SMBPrivilegeConfig) -> SMBPrivilegeResult:
        budget = (
            per_host_budget
            if per_host_budget is not None
            else max(float(cfg.timeout) * 3.0, 45.0)
        )
        async with semaphore:
            started = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    check_smb_privilege(cfg), timeout=budget
                )
            except (asyncio.TimeoutError, TimeoutError):
                result = SMBPrivilegeResult(
                    target_ip=cfg.target_ip,
                    target_hostname=cfg.target_hostname,
                    username=cfg.username,
                    domain=cfg.domain,
                    status=SMBPrivilegeStatus.UNREACHABLE,
                    error=(
                        f"per-host budget exceeded ({budget:.0f}s) — host accepted "
                        "TCP but hung the SMB negotiate / Kerberos"
                    ),
                )
            elapsed = time.monotonic() - started
        host_label = cfg.target_hostname or cfg.target_ip
        timings.append((host_label, elapsed, result.status.value))
        if elapsed >= slow_host_threshold_s:
            print_info_debug(
                f"[smb_privilege] slow host {host_label}: {elapsed:.1f}s "
                f"(status={result.status.value}) — this is what holds up the sweep"
            )
        return result

    sweep_started = time.monotonic()
    results = list(await asyncio.gather(*(_bounded(c) for c in configs)))
    sweep_elapsed = time.monotonic() - sweep_started

    if timings:
        slowest = sorted(timings, key=lambda item: item[1], reverse=True)[:3]
        slow_summary = ", ".join(
            f"{host}={elapsed:.1f}s({status})" for host, elapsed, status in slowest
        )
        print_info_debug(
            f"[smb_privilege] batch timing: {len(timings)} hosts in "
            f"{sweep_elapsed:.1f}s wall (concurrency={max_concurrency}); "
            f"slowest: {slow_summary}"
        )

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_auth_protocol(connection: object) -> str | None:
    """Best-effort detection of which auth protocol was negotiated."""
    try:
        # aiosmb stores the SPNEGO/auth context on the connection object
        spnego = getattr(connection, "gss_ctx", None) or getattr(connection, "_spnego", None)
        if spnego is None:
            return None
        name = type(spnego).__name__.lower()
        if "kerberos" in name or "krb" in name:
            return "Kerberos"
        if "ntlm" in name:
            return "NTLM"
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Credential-style adapter for cli/creds.py
# ---------------------------------------------------------------------------

def _looks_like_nt_hash(value: str) -> bool:
    """Return True when *value* is a 32-char hex NT hash."""
    if not isinstance(value, str) or len(value) != 32:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


async def verify_domain_user_local_admin(
    *,
    domain: str,
    username: str,
    credential: str,
    host: str,
    target_hostname: str | None = None,
    auth_domain: str | None = None,
    kdc_ip: str | None = None,
    timeout: int = 15,
) -> SMBPrivilegeResult:
    """Verify a domain user has local admin on a host via native aiosmb.

    Wraps :func:`check_smb_privilege` with credential auto-detection
    (cleartext password vs NT hash via 32-hex shape) and the
    NTLM/Kerberos fallback already baked into ``smb_machine_with_fallback``.

    Args:
        domain: AD domain of the credential.
        username: Account to test.
        credential: Either a cleartext password or a 32-hex NT hash.
        host: Target host IP or FQDN.
        target_hostname: Optional FQDN for Kerberos SPN matching.
        auth_domain: Credential domain when different from target domain
            (cross-domain scenarios).
        kdc_ip: KDC for ``auth_domain`` (Kerberos cross-domain).
        timeout: Per-host connection timeout.

    Returns:
        SMBPrivilegeResult — caller checks ``.is_admin`` for the Pwn3d!
        success path. Never raises; internal failures are mapped to
        ``SMBPrivilegeStatus.ERROR``.
    """
    try:
        is_hash = _looks_like_nt_hash(credential)
        cfg = SMBPrivilegeConfig(
            target_ip=host,
            target_hostname=target_hostname,
            domain=domain,
            username=username,
            password=None if is_hash else credential,
            nt_hash=credential if is_hash else None,
            auth_domain=auth_domain,
            kdc_ip=kdc_ip,
            timeout=timeout,
        )
        return await check_smb_privilege(cfg)
    except Exception as exc:  # noqa: BLE001 — must never raise to caller
        telemetry.capture_exception(exc)
        return SMBPrivilegeResult(
            target_ip=host,
            target_hostname=target_hostname,
            username=username,
            domain=domain,
            status=SMBPrivilegeStatus.ERROR,
            error=str(exc),
        )
