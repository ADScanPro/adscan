"""PrinterBug-as-CVE — MS-RPRN coercion *surface* check.

Distinct from the unified coercion adapter in
:mod:`adscan_internal.services.cve_scanner.checks.coercion`:

* The coercion adapter only confirms PrinterBug after a real SMB/HTTP
  callback fires against an ADscan-controlled listener. That requires
  reachable callback infrastructure and is the *runtime-confirmed*
  signal.
* This check reports the host as Vulnerable when the **spool service
  surface alone is reachable**: an authenticated RPC bind to MS-RPRN on
  ``\\PIPE\\spoolss`` succeeds AND ``RpcOpenPrinterEx`` (or its v1
  fallback ``RpcOpenPrinter``) succeeds. The presence of this surface
  is itself the relay/coercion enabler — even when we cannot stand up a
  callback listener (restricted egress, CI environments, customer
  policies), we still emit a finding so the CISO sees the surface.

Both rows live in the catalog because they answer different questions:
"is the surface there at all?" (this check) vs "did we trigger it on a
listener?" (the coercion adapter).
"""

from __future__ import annotations

import asyncio
import threading
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


CVE_ID = "ADSCAN-PRINTERBUG-SURFACE"
AKA = "PrinterBugSurface"
CVSS_V3 = 7.5
CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"


# impacket's NDR endpoint maps and DCERPC connection caches mutate
# global state during ``connect``/``bind``. The runner schedules
# concurrent probes (per-host concurrency=3, global=10) and races on
# those structures yield non-deterministic ``rpc_bound=False`` for hosts
# that are actually reachable — which flips PrinterBugSurface between
# Vulnerable and NotApplicable across runs of the same host (Bug 4 in
# the cves scan handoff). Serialising the impacket section is the same
# pattern used by ``_ntlm_mic_probe.py::_PATCH_LOCK``; the smallest
# defensible fix until impacket is replaced by a native MS-RPRN client.
_IMPACKET_PROBE_LOCK = threading.Lock()


@dataclass(frozen=True)
class PrinterBugSurfaceProbeResult:
    """Outcome of one PrinterBug-surface probe."""

    rpc_bound: bool
    open_printer_succeeded: bool
    error: str | None = None
    notes: tuple[str, ...] = ()


def _probe_printerbug_surface_sync(
    *,
    host: str,
    username: str | None,
    password: str | None,
    domain: str | None,
    nt_hash: str | None,
) -> PrinterBugSurfaceProbeResult:
    """Synchronous MS-RPRN bind + OpenPrinter probe."""
    try:
        from impacket.dcerpc.v5 import rprn, transport
        from impacket.dcerpc.v5.rpcrt import DCERPCException
    except ImportError as exc:  # pragma: no cover
        return PrinterBugSurfaceProbeResult(
            rpc_bound=False,
            open_printer_succeeded=False,
            error=f"impacket missing: {exc}",
        )

    binding = rf"ncacn_np:{host}[\PIPE\spoolss]"
    # See module-level comment on ``_IMPACKET_PROBE_LOCK`` — impacket
    # globals are not thread-safe so we serialise the whole RPC dance.
    with _IMPACKET_PROBE_LOCK:
        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.set_dport(445)
        if hasattr(rpc_transport, "setRemoteHost"):
            rpc_transport.setRemoteHost(host)
        if hasattr(rpc_transport, "set_credentials"):
            rpc_transport.set_credentials(
                username or "", password or "", domain or "", "", nt_hash or ""
            )
        notes: list[str] = []
        try:
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as exc:  # noqa: BLE001
            return PrinterBugSurfaceProbeResult(
                rpc_bound=False,
                open_printer_succeeded=False,
                error=f"bind error: {exc}",
                notes=("could not bind to MS-RPRN — spooler likely disabled",),
            )

        try:
            printer = f"\\\\{host}\x00"
            try:
                rprn.hRpcOpenPrinterEx(dce, printer, "", None, "", 0)
                notes.append("RpcOpenPrinterEx succeeded — surface open")
                return PrinterBugSurfaceProbeResult(
                    rpc_bound=True,
                    open_printer_succeeded=True,
                    notes=tuple(notes),
                )
            except DCERPCException as exc:
                notes.append(f"RpcOpenPrinterEx DCERPCException: {exc}")
            except Exception as exc:  # noqa: BLE001
                notes.append(f"RpcOpenPrinterEx unexpected: {exc}")

            try:
                rprn.hRpcOpenPrinter(dce, printer)
                notes.append("RpcOpenPrinter succeeded — surface open (v1)")
                return PrinterBugSurfaceProbeResult(
                    rpc_bound=True,
                    open_printer_succeeded=True,
                    notes=tuple(notes),
                )
            except Exception as exc:  # noqa: BLE001
                notes.append(f"RpcOpenPrinter failed: {exc}")
                return PrinterBugSurfaceProbeResult(
                    rpc_bound=True,
                    open_printer_succeeded=False,
                    notes=tuple(notes),
                )
        finally:
            try:
                dce.disconnect()
            except Exception:  # noqa: BLE001
                pass


class PrinterBugSurfaceCheck:
    """Detect MS-RPRN coercion *surface* via authenticated RPC bind + open."""

    cve_id: str = CVE_ID

    def __init__(self, *, probe: Any | None = None) -> None:
        self._probe = probe or _probe_printerbug_surface_sync

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        del ctx
        if creds is None:
            return [
                _error(target.host, "PrinterBug surface probe requires authentication")
            ]

        username = getattr(creds, "username", None)
        password = getattr(creds, "password", None)
        domain = getattr(creds, "target_domain", None) or getattr(creds, "domain", None)
        nt_hash = getattr(creds, "nt_hash", None)

        print_info_verbose(
            f"[printerbug-surface] probing {mark_sensitive(target.host, 'host')}"
        )
        try:
            probe = await asyncio.to_thread(
                self._probe,
                host=target.host,
                username=username,
                password=password,
                domain=domain,
                nt_hash=nt_hash,
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(
                f"[printerbug-surface] probe crashed against {target.host}: {exc}"
            )
            return [_error(target.host, str(exc))]
        return [_result_from_probe(target.host, probe)]


def _result_from_probe(host: str, probe: PrinterBugSurfaceProbeResult) -> CVEResult:
    payload = {
        "rpc_bound": probe.rpc_bound,
        "open_printer_succeeded": probe.open_printer_succeeded,
        "notes": list(probe.notes),
        "error": probe.error,
    }
    if not probe.rpc_bound:
        return CVEResult(
            cve_id=CVE_ID,
            aka=AKA,
            host=host,
            status=CVEStatus.NOT_APPLICABLE,
            severity=Severity.from_cvss(CVSS_V3),
            cvss_v3=CVSS_V3,
            cvss_vector=CVSS_VECTOR,
            evidence=Evidence(
                summary="MS-RPRN not reachable — spool surface absent",
                payload=payload,
            ),
        )
    status = (
        CVEStatus.VULNERABLE
        if probe.open_printer_succeeded
        else CVEStatus.NOT_VULNERABLE
    )
    summary = (
        "PrinterBug coercion surface present — RpcOpenPrinter(Ex) succeeded"
        if probe.open_printer_succeeded
        else "MS-RPRN bound but RpcOpenPrinter(Ex) failed — surface restricted"
    )
    return CVEResult(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        status=status,
        severity=Severity.from_cvss(CVSS_V3),
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        evidence=Evidence(summary=summary, payload=payload),
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
        evidence=Evidence(
            summary=f"PrinterBug surface probe error: {message}", payload={}
        ),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "PrinterBugSurfaceCheck",
    "PrinterBugSurfaceProbeResult",
]
