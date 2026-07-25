# Parity with netexec is the contract here — inherits netexec's permissive fall-through.
# Known FP on hosts where the spool API is reachable but the host is patched.
# Source: reference/NetExec/nxc/modules/printnightmare.py:110-111.
"""PrintNightmare (CVE-2021-34527) native check — netexec parity.

Bind to MS-RPRN over ``\\PIPE\\spoolss``, build a ``DRIVER_INFO_2`` with
**all NULL fields** (cVersion=0, every name pointer NULL — exactly as
netexec does at ``printnightmare.py:73-92``), then call
``RpcAddPrinterDriverEx``.

Decision tree (replicates ``printnightmare.py:93-111`` verbatim):

* ``RPC_E_ACCESS_DENIED`` (0x8001011B) → ``NotVulnerable``
* ``ERROR_INVALID_PARAMETER`` (0x57) → ``Vulnerable``
* ``DCERPCException`` whose mapped status is ``rpc_s_access_denied`` →
  ``NotVulnerable``
* Anything else, including no exception → ``Vulnerable``
  (netexec's permissive fall-through, ``return True`` at line 110-111)

Restrictive-AD constraints (per ``adscan-ad-constraints``):

* The SMB session is opened with the user's **auth_domain** (where the
  account lives), not the target_domain. Cross-realm SMB to a foreign
  DC without a trust path returns ``STATUS_LOGON_FAILURE`` — the runner
  catches that and emits ``SKIPPED`` rather than a misleading
  ``NotApplicable`` (which would suggest the spooler is filtered).
* Kerberos is preferred when explicitly requested (``creds.use_kerberos``
  or ``ctx`` provides a kdc_ip). The probe wires impacket's
  ``set_kerberos(True, kdcHost=...)`` so cross-realm Kerberos referrals
  work via the underlying impacket flow. NTLM is the fallback for
  environments where Kerberos is unreachable.
* Clock skew on Kerberos is handled by impacket's internal retry loop
  on ``KRB_AP_ERR_SKEW``; ADscan's ``kerberos_transport`` wrapper is
  the canonical path for code that issues TGTs/TGSes directly, but the
  spooler bind path is owned by impacket so we let it negotiate.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from adscan_core import telemetry
from adscan_core.rich_output import print_error, print_info_verbose
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services.cve_scanner.result import (
    CVEResult,
    CVEStatus,
    Evidence,
    Severity,
)
from adscan_core.rich_output import print_exception

if TYPE_CHECKING:  # pragma: no cover
    from adscan_internal.services.cve_scanner.runner import ScanContext, ScanTarget


CVE_ID = "CVE-2021-34527"
AKA = "PrintNightmare"
CVSS_V3 = 8.8
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"

# Win32/HRESULT codes — see netexec printnightmare.py:97-101,140.
RPC_E_ACCESS_DENIED = 0x8001011B
ERROR_INVALID_PARAMETER = 0x57

# MS-RPRN APD_* flags (printnightmare.py:132-134).
APD_COPY_ALL_FILES = 0x00000004
APD_COPY_FROM_DIRECTORY = 0x00000010
APD_INSTALL_WARNED_DRIVER = 0x00008000
_ADD_DRIVER_FLAGS = (
    APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | APD_INSTALL_WARNED_DRIVER
)


# Substring markers indicating that an SMB bind-time auth failure is best
# classified as a cross-realm credential failure (per the AD-constraints
# checklist) rather than a "spooler not reachable" verdict.
_AUTH_FAILURE_MARKERS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_NO_LOGON_SERVERS",
    "STATUS_ACCESS_DENIED",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "KDC_ERR_WRONG_REALM",
    "KDC_ERR_PREAUTH_FAILED",
    "logon failure",
    "wrong password",
)


@dataclass(frozen=True)
class PrintNightmareProbeResult:
    """Outcome of one PrintNightmare probe."""

    spooler_reachable: bool
    add_driver_error_code: int | None
    add_driver_error_text: str | None
    vulnerable: bool
    notes: tuple[str, ...] = ()
    auth_failure: bool = False


def _probe_printnightmare_sync(
    *,
    host: str,
    username: str | None,
    password: str | None,
    domain: str | None,
    nt_hash: str | None,
    use_kerberos: bool = False,
    kdc_host: str | None = None,
    target_hostname: str | None = None,
) -> PrintNightmareProbeResult:
    """Synchronous probe — call from a worker thread.

    Mirrors ``reference/NetExec/nxc/modules/printnightmare.py:39-111``.

    Args:
        host: Target IP / hostname (named-pipe binding host).
        username: Authenticated user (no realm prefix).
        password: Plaintext password (or empty when ``nt_hash`` is set).
        domain: ``auth_domain`` — realm where the account lives.
        nt_hash: NT hash for pass-the-hash / Kerberos RC4-key paths.
        use_kerberos: Switch impacket's DCERPC transport into Kerberos
            mode. Required when NTLM is GPO-disabled.
        kdc_host: KDC IP/host for Kerberos auth (passed to impacket
            ``set_kerberos(True, kdcHost=...)``).
        target_hostname: SPN host for Kerberos (e.g. ``dc01.essos.local``).
            When unset and Kerberos is in use, impacket may fail with
            ``KDC_ERR_S_PRINCIPAL_UNKNOWN`` against an IP target.
    """
    try:
        from impacket.dcerpc.v5 import rprn, transport
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.dcerpc.v5.rpcrt import DCERPCException, rpc_status_codes
    except ImportError as exc:  # pragma: no cover
        return PrintNightmareProbeResult(
            spooler_reachable=False,
            add_driver_error_code=None,
            add_driver_error_text=f"impacket missing: {exc}",
            vulnerable=False,
        )

    # Use the SPN-friendly hostname when running Kerberos; the IP host is
    # required when running NTLM (named-pipe over SMB to the literal IP).
    bind_host = target_hostname if (use_kerberos and target_hostname) else host
    binding = rf"ncacn_np:{bind_host}[\PIPE\spoolss]"
    rpc_transport = transport.DCERPCTransportFactory(binding)
    rpc_transport.set_dport(445)
    if hasattr(rpc_transport, "setRemoteHost"):
        rpc_transport.setRemoteHost(host)
    if hasattr(rpc_transport, "set_credentials"):
        rpc_transport.set_credentials(
            username or "",
            password or "",
            domain or "",
            "",
            nt_hash or "",
        )
    if use_kerberos and hasattr(rpc_transport, "set_kerberos"):
        # impacket's set_kerberos(True, kdcHost=...) toggles GSSAPI/SPNEGO
        # on the underlying SMB session; clock skew is handled internally.
        rpc_transport.set_kerberos(True, kdcHost=kdc_host or host)

    notes: list[str] = []
    try:
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(rprn.MSRPC_UUID_RPRN)
    except Exception as exc:  # noqa: BLE001
        err_text = f"bind error: {exc}"
        upper = str(exc).upper()
        is_auth_failure = any(m.upper() in upper for m in _AUTH_FAILURE_MARKERS)
        return PrintNightmareProbeResult(
            spooler_reachable=False,
            add_driver_error_code=None,
            add_driver_error_text=err_text,
            vulnerable=False,
            notes=("could not bind to MS-RPRN",),
            auth_failure=is_auth_failure,
        )

    try:
        # All-NULL DRIVER_INFO_2 — netexec printnightmare.py:75-84.
        driver_container = rprn.DRIVER_CONTAINER()
        driver_container["Level"] = 2
        driver_container["DriverInfo"]["tag"] = 2
        driver_container["DriverInfo"]["Level2"]["cVersion"] = 0
        driver_container["DriverInfo"]["Level2"]["pName"] = NULL
        driver_container["DriverInfo"]["Level2"]["pEnvironment"] = NULL
        driver_container["DriverInfo"]["Level2"]["pDriverPath"] = NULL
        driver_container["DriverInfo"]["Level2"]["pDataFile"] = NULL
        driver_container["DriverInfo"]["Level2"]["pConfigFile"] = NULL

        error_code: int | None = None
        error_text: str | None = None
        # Default verdict mirrors netexec's permissive fall-through
        # (``return True`` at printnightmare.py:110-111).
        vulnerable = True

        try:
            rprn.hRpcAddPrinterDriverEx(dce, NULL, driver_container, _ADD_DRIVER_FLAGS)
            error_code = 0
            error_text = "STATUS_SUCCESS — call accepted"
            notes.append(
                "AddPrinterDriverEx returned success — fall-through Vulnerable"
            )
        except DCERPCException as exc:
            error_text = str(exc)
            code = getattr(exc, "error_code", None)
            if isinstance(code, int):
                error_code = code

            if code == RPC_E_ACCESS_DENIED:
                vulnerable = False
                notes.append("RPC_E_ACCESS_DENIED (0x8001011B) — patched")
            elif code == ERROR_INVALID_PARAMETER:
                vulnerable = True
                notes.append("ERROR_INVALID_PARAMETER (0x57) — Vulnerable")
            else:
                # Generic DCERPCException — check the rpc_status_codes mapping
                # for ``rpc_s_access_denied`` (printnightmare.py:105-108).
                mapped: str | None = None
                try:
                    mapped = (
                        rpc_status_codes.get(code) if isinstance(code, int) else None
                    )
                except Exception:  # noqa: BLE001
                    mapped = None
                if mapped == "rpc_s_access_denied":
                    vulnerable = False
                    notes.append("rpc_s_access_denied — patched")
                else:
                    # Fall-through: netexec prints "Unexpected error" but
                    # then unconditionally highlights Vulnerable.
                    notes.append(
                        f"unexpected DCERPC error {error_text!r} — fall-through Vulnerable"
                    )
        except Exception as exc:  # noqa: BLE001
            error_text = f"transport error: {exc}"
            notes.append(f"transport error during AddPrinterDriverEx: {exc}")
            # Non-DCERPC transport errors → still Vulnerable (parity).

        return PrintNightmareProbeResult(
            spooler_reachable=True,
            add_driver_error_code=error_code,
            add_driver_error_text=error_text,
            vulnerable=vulnerable,
            notes=tuple(notes),
        )
    finally:
        try:
            dce.disconnect()
        except Exception:  # noqa: BLE001
            pass


class PrintNightmareCheck:
    """Probe-only PrintNightmare detection — netexec parity.

    Cross-realm policy: the SMB session uses the **auth_domain** (where
    the user account lives) as the credential realm. When the resulting
    bind fails with an authentication-class error and ``auth_domain``
    differs from ``target_domain``, the verdict is ``SKIPPED`` — there
    is genuinely no answer to "is this DC vulnerable?" without a
    target-realm credential or a real cross-realm trust path.
    """

    cve_id: str = CVE_ID

    def __init__(self, *, probe: Any | None = None) -> None:
        self._probe = probe or _probe_printnightmare_sync

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        """Run the PrintNightmare probe against ``target``."""
        del ctx
        if creds is None:
            return [_error(target.host, "PrintNightmare probe requires authentication")]

        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        # Auth-domain (creds.domain) is where the user lives. target_domain
        # is informational; SMB credentials always resolve in auth_domain.
        auth_domain = getattr(creds, "auth_domain", None) or getattr(
            creds, "domain", None
        )
        target_domain = getattr(creds, "target_domain", None) or auth_domain
        nt_hash = getattr(creds, "nt_hash", None)
        use_kerberos = bool(getattr(creds, "use_kerberos", False))
        kdc_host = getattr(creds, "kdc_ip", None) or getattr(creds, "auth_kdc_ip", None)
        target_hostname = target.display_name

        cross_realm = (
            target_domain is not None
            and auth_domain is not None
            and target_domain.lower() != auth_domain.lower()
        )

        print_info_verbose(
            f"[printnightmare] probing {mark_sensitive(target.host, 'host')} "
            f"(auth_realm={mark_sensitive(auth_domain or '?', 'domain')}, "
            f"target_realm={mark_sensitive(target_domain or '?', 'domain')}, "
            f"kerberos={use_kerberos})"
        )
        try:
            result = await asyncio.to_thread(
                self._probe,
                host=target.host,
                username=username,
                password=password,
                domain=auth_domain,
                nt_hash=nt_hash,
                use_kerberos=use_kerberos,
                kdc_host=kdc_host,
                target_hostname=target_hostname,
            )
        except TypeError:
            # Backwards-compatible call for legacy probes (test injections)
            # that only accept the original 5-argument signature.
            result = await asyncio.to_thread(
                self._probe,
                host=target.host,
                username=username,
                password=password,
                domain=auth_domain,
                nt_hash=nt_hash,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[printnightmare] probe crashed against {target.host}: {exc}")
            return [_error(target.host, str(exc))]

        return [_result_from_probe(target.host, result, cross_realm=cross_realm)]


def _result_from_probe(
    host: str, probe: PrintNightmareProbeResult, *, cross_realm: bool = False
) -> CVEResult:
    """Map a :class:`PrintNightmareProbeResult` to a :class:`CVEResult`.

    Cross-realm authentication failures are surfaced as ``SKIPPED`` so
    the lab harness counts them as a documented per-target outcome, not
    a misleading ``NotApplicable`` (which would suggest the spooler is
    filtered).
    """
    base = dict(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        severity=Severity.from_cvss(CVSS_V3),
    )
    payload = {
        "spooler_reachable": probe.spooler_reachable,
        "add_driver_error_code": probe.add_driver_error_code,
        "add_driver_error_text": probe.add_driver_error_text,
        "notes": list(probe.notes),
        "auth_failure": probe.auth_failure,
    }
    if probe.auth_failure and cross_realm:
        return CVEResult(
            **base,
            status=CVEStatus.SKIPPED,
            evidence=Evidence(
                summary=(
                    "PrintNightmare bind rejected — cross-realm creds not "
                    "authorized; no trust path tested"
                ),
                payload=payload,
            ),
        )
    if not probe.spooler_reachable:
        return CVEResult(
            **base,
            status=CVEStatus.NOT_APPLICABLE,
            evidence=Evidence(
                summary="MS-RPRN not reachable — spooler disabled or filtered",
                payload=payload,
            ),
        )
    status = CVEStatus.VULNERABLE if probe.vulnerable else CVEStatus.NOT_VULNERABLE
    summary = (
        "PrintNightmare surface confirmed via RpcAddPrinterDriverEx"
        if probe.vulnerable
        else "PrintNightmare not exploitable (ACCESS_DENIED)"
    )
    return CVEResult(
        **base, status=status, evidence=Evidence(summary=summary, payload=payload)
    )


def _error(host: str, message: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.ERROR,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        error=message,
        evidence=Evidence(summary=f"PrintNightmare error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "ERROR_INVALID_PARAMETER",
    "PrintNightmareCheck",
    "PrintNightmareProbeResult",
    "RPC_E_ACCESS_DENIED",
]
