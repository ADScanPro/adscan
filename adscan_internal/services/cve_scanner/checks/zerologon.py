"""Zerologon (CVE-2020-1472) native check — netexec parity.

Probes MS-NRPC ``NetrServerAuthenticate3`` with an all-zero client
credential. Vulnerable DCs return ``ErrorCode == 0`` (the cryptographic
predicate held); patched DCs return ``STATUS_ACCESS_DENIED``
(``0xC0000022``) on every attempt.

The transport mirrors netexec's ``zerologon`` module verbatim:
``epm.hept_map`` → ``ncacn_ip_tcp`` binding (not ``\\PIPE\\netlogon``),
``hNetrServerAuthenticate3`` (not ``Authenticate2``), 2000 attempts
(false-negative rate 0.04% per netexec's note). Source citation:
``reference/NetExec/nxc/modules/zerologon.py:11,29-65,73-107``.

We never reset the DC machine password — the probe stops as soon as the
auth bypass is proven (terminating ``ErrorCode == 0``). The synchronous
impacket call is offloaded to a worker thread so the async runner stays
responsive.
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


CVE_ID = "CVE-2020-1472"
AKA = "Zerologon"
CVSS_V3 = 10.0
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
# 2000 attempts — netexec parity, ``MAX_ATTEMPTS`` at zerologon.py:11.
DEFAULT_MAX_ATTEMPTS = 2000

# Per-attempt outcome contract (also used by the L1 probe seam).
_NT_STATUS_ACCESS_DENIED = 0xC0000022


@dataclass(frozen=True)
class ZerologonProbeResult:
    """Outcome of one safe Zerologon authentication probe."""

    vulnerable: bool
    attempts: int
    last_error: str | None = None
    nt_status: int | None = None
    # When the loop terminates due to an unexpected NTSTATUS we surface it
    # as Error (netexec's ``sys.exit(2)`` is a CLI artifact — the closest
    # CVEStatus mapping is ``ERROR``).
    unexpected_status: bool = False


def _derive_dc_short_name(target: "ScanTarget") -> str:
    """Best-effort short NetBIOS-style DC name for the auth call."""
    name = target.display_name or target.host
    if "." in name:
        name = name.split(".", 1)[0]
    return name.upper()


def _probe_zerologon_sync(
    *,
    dc_ip: str,
    dc_short_name: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> ZerologonProbeResult:
    """Run the synchronous MS-NRPC ``Authenticate3`` probe.

    Mirrors ``reference/NetExec/nxc/modules/zerologon.py:46-107``:
    EPM-mapped ``ncacn_ip_tcp`` binding, 2000-attempt loop, single
    ``hNetrServerAuthenticate3`` per iteration. Returns a
    :class:`ZerologonProbeResult`; never resets the DC password.

    Args:
        dc_ip: The DC's IP — used as ``remoteHost`` for ``epm.hept_map``.
        dc_short_name: Hostname (no domain), e.g. ``DC01``. Used as
            ``dc_handle`` (``\\\\<hostname>``) and ``target_computer``.
        max_attempts: Probe budget. Defaults to ``DEFAULT_MAX_ATTEMPTS``.

    Returns:
        ZerologonProbeResult capturing the verdict and any observed
        NTSTATUS for the last attempt.
    """
    try:
        from impacket.dcerpc.v5 import epm, nrpc, transport
        from impacket.dcerpc.v5.rpcrt import DCERPCException
    except ImportError as exc:  # pragma: no cover - impacket pinned in deps
        return ZerologonProbeResult(
            vulnerable=False, attempts=0, last_error=f"impacket missing: {exc}"
        )

    # Bind via EPM → ncacn_ip_tcp (parity with netexec zerologon.py:51-56).
    try:
        binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
        rpc_transport = transport.DCERPCTransportFactory(binding)
        if hasattr(rpc_transport, "setRemoteHost"):
            rpc_transport.setRemoteHost(dc_ip)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)
    except Exception as exc:  # noqa: BLE001 — surface as bind error
        return ZerologonProbeResult(
            vulnerable=False, attempts=0, last_error=f"bind error: {exc}"
        )

    dc_handle = "\\\\" + dc_short_name
    target_computer = dc_short_name
    account_name = dc_short_name + "$"
    secure_channel_type = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    flags = 0x212FFFFF
    plaintext = b"\x00" * 8
    ciphertext = b"\x00" * 8

    last_error: str | None = None
    nt_status: int | None = None
    attempts = 0
    unexpected = False
    try:
        for attempts in range(1, max_attempts + 1):
            try:
                # Per netexec, a fresh ReqChallenge precedes each Authenticate3.
                nrpc.hNetrServerReqChallenge(
                    dce, dc_handle + "\x00", target_computer + "\x00", plaintext
                )
                server_auth = nrpc.hNetrServerAuthenticate3(
                    dce,
                    dc_handle + "\x00",
                    account_name + "\x00",
                    secure_channel_type,
                    target_computer + "\x00",
                    ciphertext,
                    flags,
                )
                if server_auth["ErrorCode"] == 0:
                    return ZerologonProbeResult(
                        vulnerable=True, attempts=attempts, nt_status=0
                    )
            except DCERPCException as exc:
                last_error = str(exc)
                code = getattr(exc, "error_code", None)
                if isinstance(code, int):
                    nt_status = code
                if code == _NT_STATUS_ACCESS_DENIED:
                    continue
                # Anything else: surface as Error per the operator decision
                # (netexec calls ``sys.exit(2)`` here — CLI artifact, not a
                # status we can express).
                unexpected = True
                last_error = (
                    f"unexpected NTSTATUS during authenticate3 loop: "
                    f"{code if code is not None else exc}"
                )
                break
            except Exception as exc:  # noqa: BLE001
                last_error = f"transport error: {exc}"
                unexpected = True
                break
    finally:
        try:
            dce.disconnect()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass

    return ZerologonProbeResult(
        vulnerable=False,
        attempts=attempts,
        last_error=last_error,
        nt_status=nt_status,
        unexpected_status=unexpected,
    )


class ZerologonCheck:
    """Native MS-NRPC Zerologon detection check (safe, read-only)."""

    cve_id: str = CVE_ID

    def __init__(
        self,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        probe: Any | None = None,
    ) -> None:
        self._max_attempts = max_attempts
        # ``probe`` is an injection point for unit tests — defaults to the
        # real synchronous impacket probe.
        self._probe = probe or _probe_zerologon_sync

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        """Run the Zerologon probe against ``target`` (must be a DC)."""
        del creds, ctx  # unauthenticated probe — no creds needed
        if not target.is_dc:
            return [_not_applicable(target.host, "target is not a domain controller")]

        dc_short = _derive_dc_short_name(target)
        print_info_verbose(
            "[zerologon] probing "
            f"{mark_sensitive(target.host, 'host')} "
            f"(short={mark_sensitive(dc_short, 'host')})"
        )
        try:
            probe_result = await asyncio.to_thread(
                self._probe,
                dc_ip=target.host,
                dc_short_name=dc_short,
                max_attempts=self._max_attempts,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[zerologon] probe crashed against {target.host}: {exc}")
            return [_error(target.host, str(exc))]

        return [_result_from_probe(target.host, probe_result)]


def _result_from_probe(host: str, probe: ZerologonProbeResult) -> CVEResult:
    """Map a :class:`ZerologonProbeResult` to a :class:`CVEResult`."""
    if probe.vulnerable:
        summary = (
            "Zerologon confirmed: NetrServerAuthenticate3 returned "
            f"ErrorCode=0 after {probe.attempts} attempt(s)"
        )
        return CVEResult(
            cve_id=CVE_ID,
            aka=AKA,
            host=host,
            status=CVEStatus.VULNERABLE,
            severity=Severity.from_cvss(CVSS_V3),
            cvss_v3=CVSS_V3,
            cvss_vector=CVSS_VECTOR,
            evidence=Evidence(
                summary=summary,
                payload={
                    "attempts": probe.attempts,
                    "max_attempts": DEFAULT_MAX_ATTEMPTS,
                    "side_effect": "none — probe stopped after auth bypass",
                },
            ),
        )
    if probe.last_error and probe.attempts == 0:
        return _error(host, probe.last_error)
    if probe.unexpected_status:
        return _error(host, probe.last_error or "unexpected NTSTATUS")
    summary = f"Zerologon not vulnerable after {probe.attempts} attempt(s)" + (
        f" — last error: {probe.last_error}" if probe.last_error else ""
    )
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.NOT_VULNERABLE,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(
            summary=summary,
            payload={
                "attempts": probe.attempts,
                "last_nt_status": probe.nt_status,
                "last_error": probe.last_error,
            },
        ),
    )


def _not_applicable(host: str, reason: str) -> CVEResult:
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=CVEStatus.NOT_APPLICABLE,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=reason, payload={"reason": reason}),
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
        evidence=Evidence(summary=f"Zerologon probe error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "DEFAULT_MAX_ATTEMPTS",
    "ZerologonCheck",
    "ZerologonProbeResult",
]
