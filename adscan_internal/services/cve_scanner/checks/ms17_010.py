"""MS17-010 / EternalBlue (CVE-2017-0144) native check.

Probe-only. We craft a NetBIOS-framed SMBv1 NEGOTIATE followed by an
SMBv1 Trans2 SESSION_SETUP with sub-command ``SESSION_SETUP`` (0x000E)
that triggers ``STATUS_INSUFF_SERVER_RESOURCES`` (``0xC0000205``) on
vulnerable hosts and a different NTSTATUS (typically
``STATUS_NOT_IMPLEMENTED`` / ``STATUS_INVALID_PARAMETER``) on patched
hosts. This is the canonical Metasploit/auxiliary detection signature.

Why raw SMBv1 (rather than aiosmb or SMB transport service):
    aiosmb is SMBv2/3 only and intentionally never speaks SMB1.
    smb_transport's factories are SMBv2/3-bound. MS17-010 strictly
    requires SMBv1 — so we hand-build the two SMBv1 packets needed for
    detection over a raw TCP socket. No SMBv1 client library is added to
    the runtime.

The probe never sends the EternalBlue payload — only the detection
session-setup that classifies the host.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable

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


CVE_ID = "CVE-2017-0144"
AKA = "MS17-010"
# NVD canonical CVSS v3 base score for CVE-2017-0144 = 8.1.
CVSS_V3 = 8.1
CVSS_VECTOR = "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"

# NTSTATUS classification.
STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
STATUS_NOT_SUPPORTED = 0xC00000BB

# SMBv1 NEGOTIATE request — fixed bytes negotiating the "NT LM 0.12" dialect.
# Header: SMB_COM_NEGOTIATE (0x72), flags/flags2 standard.
_SMB1_NEGOTIATE = bytes.fromhex(
    "00000054"  # NetBIOS session: length = 0x54
    "ff534d42"  # 'SMB\xff'
    "72"  # SMB_COM_NEGOTIATE
    "00000000"  # NTStatus = 0
    "18"  # Flags
    "53c8"  # Flags2 (UNICODE | NT_STATUS | EXTENDED_SECURITY | LONG_NAMES_ALLOWED)
    "0000"  # PIDHigh
    "0000000000000000"  # SecurityFeatures
    "0000"  # Reserved
    "0000"  # TID
    "2f4b"  # PID
    "0000"  # UID
    "c5fe"  # MID
    "00"  # WordCount = 0
    "3100"  # ByteCount = 49
    "0250432031204e4554574f524b2050524f4752414d20312e3000"  # PC NETWORK PROGRAM 1.0
    "024c414e4d414e312e3000"  # LANMAN1.0
    "024c414e4d414e322e3100"  # LANMAN2.1
    "024e54204c4d20302e313200"  # NT LM 0.12
)

# SMBv1 Trans2 SESSION_SETUP probe with crafted parameters that
# overflow the input buffer accounting in vulnerable srv.sys, returning
# STATUS_INSUFF_SERVER_RESOURCES. Layout follows the
# auxiliary/scanner/smb/smb_ms17_010 Metasploit module signature.
_SMB1_TRANS2_SESSION_SETUP = bytes.fromhex(
    "0000004a"  # NetBIOS session length = 0x4a
    "ff534d42"  # 'SMB\xff'
    "32"  # SMB_COM_TRANSACTION2
    "00000000"  # NTStatus = 0
    "18"  # Flags
    "07c8"  # Flags2
    "0000"  # PIDHigh
    "0000000000000000"  # SecurityFeatures
    "0000"  # Reserved
    "0008"  # TID (placeholder — replaced after negotiate)
    "2f4b"  # PID
    "0000"  # UID (placeholder — replaced after negotiate)
    "c55e"  # MID
    "0f"  # WordCount = 15
    "0c00"  # TotalParameterCount = 12
    "0000"  # TotalDataCount = 0
    "0100"  # MaxParameterCount
    "0000"  # MaxDataCount
    "00"  # MaxSetupCount
    "00"  # Reserved
    "0000"  # Flags
    "a6d9a440"  # Timeout
    "0000"  # Reserved2
    "0c00"  # ParameterCount
    "4200"  # ParameterOffset
    "0000"  # DataCount
    "4e00"  # DataOffset
    "01"  # SetupCount
    "00"  # Reserved3
    "0e00"  # Setup[0] = TRANS2_SESSION_SETUP (0x000E)
    "0000"  # ByteCount
    "0c0000000400"
    "0200000000000000000000000000"
)


@dataclass(frozen=True)
class MS17ProbeResult:
    """Outcome of an MS17-010 probe."""

    vulnerable: bool
    not_applicable: bool
    nt_status: int | None
    summary: str
    error: str | None = None


# Probe seam: callable that takes (host, port, timeout) and returns an
# :class:`MS17ProbeResult`. Tests inject a canned implementation.
ProbeFn = Callable[..., Awaitable[MS17ProbeResult]]


async def _probe_ms17_010(
    *,
    host: str,
    port: int = 445,
    timeout: float = 10.0,
) -> MS17ProbeResult:
    """Real raw-TCP SMBv1 probe."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError) as exc:
        return MS17ProbeResult(
            vulnerable=False,
            not_applicable=False,
            nt_status=None,
            summary=f"TCP connect to {host}:{port} failed",
            error=str(exc),
        )

    try:
        # 1. NEGOTIATE
        writer.write(_SMB1_NEGOTIATE)
        await writer.drain()
        nb_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        nb_len = struct.unpack(">I", nb_header)[0] & 0x00FFFFFF
        nego_resp = await asyncio.wait_for(reader.readexactly(nb_len), timeout=timeout)
        # SMB1 reply must start with 0xff 'SMB' and command 0x72.
        if len(nego_resp) < 32 or nego_resp[:4] != b"\xffSMB" or nego_resp[4] != 0x72:
            return MS17ProbeResult(
                vulnerable=False,
                not_applicable=True,
                nt_status=None,
                summary="server did not return an SMBv1 NEGOTIATE response — SMBv1 likely disabled",
            )
        nego_status = struct.unpack("<I", nego_resp[5:9])[0]
        if nego_status == STATUS_NOT_SUPPORTED:
            return MS17ProbeResult(
                vulnerable=False,
                not_applicable=True,
                nt_status=nego_status,
                summary="server rejected SMBv1 NEGOTIATE with STATUS_NOT_SUPPORTED",
            )
        # Extract TID and UID from the NEGOTIATE response header for the
        # follow-up Trans2 packet so it sits on the negotiated session.
        tid = nego_resp[24:26]
        uid = nego_resp[28:30]

        trans2 = bytearray(_SMB1_TRANS2_SESSION_SETUP)
        # Header offsets: 4 (NB) + 24 (TID), 4 (NB) + 28 (UID).
        trans2[28:30] = tid
        trans2[32:34] = uid

        writer.write(bytes(trans2))
        await writer.drain()
        nb_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        nb_len = struct.unpack(">I", nb_header)[0] & 0x00FFFFFF
        trans_resp = await asyncio.wait_for(reader.readexactly(nb_len), timeout=timeout)
        if len(trans_resp) < 9 or trans_resp[:4] != b"\xffSMB":
            return MS17ProbeResult(
                vulnerable=False,
                not_applicable=False,
                nt_status=None,
                summary="malformed SMBv1 reply to Trans2 SESSION_SETUP",
            )
        nt_status = struct.unpack("<I", trans_resp[5:9])[0]
        if nt_status == STATUS_INSUFF_SERVER_RESOURCES:
            return MS17ProbeResult(
                vulnerable=True,
                not_applicable=False,
                nt_status=nt_status,
                summary="STATUS_INSUFF_SERVER_RESOURCES — host is MS17-010 vulnerable",
            )
        return MS17ProbeResult(
            vulnerable=False,
            not_applicable=False,
            nt_status=nt_status,
            summary=f"NTSTATUS 0x{nt_status:08x} — host is patched / not vulnerable",
        )
    except asyncio.IncompleteReadError as exc:
        return MS17ProbeResult(
            vulnerable=False,
            not_applicable=True,
            nt_status=None,
            summary="TCP connection closed by peer mid-handshake — SMBv1 likely disabled",
            error=str(exc),
        )
    except (ConnectionResetError, BrokenPipeError) as exc:
        # Hardened hosts that disable SMBv1 commonly answer the negotiate by
        # tearing the TCP session down with RST (errno 104) instead of a clean
        # STATUS_NOT_SUPPORTED reply. Per spec section 6 this maps to
        # NotApplicable, not Error.
        return MS17ProbeResult(
            vulnerable=False,
            not_applicable=True,
            nt_status=None,
            summary="SMBv1 disabled or rejected (peer reset connection)",
            error=str(exc),
        )
    except asyncio.TimeoutError as exc:
        return MS17ProbeResult(
            vulnerable=False,
            not_applicable=False,
            nt_status=None,
            summary="probe timed out waiting for SMBv1 reply",
            error=str(exc),
        )
    except OSError as exc:
        # Some asyncio backends surface peer RST as a generic OSError with
        # errno 104 (ECONNRESET) or 32 (EPIPE). Treat those as the same
        # SMBv1-disabled signal; leave other OS errors as Error.
        if getattr(exc, "errno", None) in (104, 32):
            return MS17ProbeResult(
                vulnerable=False,
                not_applicable=True,
                nt_status=None,
                summary="SMBv1 disabled or rejected (peer reset connection)",
                error=str(exc),
            )
        raise
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass


def classify_status(status: int | None) -> tuple[CVEStatus, str]:
    """Pure-logic classifier — maps NTSTATUS to scanner status.

    Args:
        status: NTSTATUS returned by the Trans2 SESSION_SETUP, or None
            when no reply was parseable.

    Returns:
        Tuple of (status, summary) for the result mapper.
    """
    if status is None:
        return CVEStatus.ERROR, "no NTSTATUS observed"
    if status == STATUS_INSUFF_SERVER_RESOURCES:
        return CVEStatus.VULNERABLE, "STATUS_INSUFF_SERVER_RESOURCES — vulnerable"
    return CVEStatus.NOT_VULNERABLE, f"NTSTATUS 0x{status:08x} — patched"


class MS17_010Check:
    """Native MS17-010 (EternalBlue) detection check (probe-only)."""

    cve_id: str = CVE_ID

    def __init__(self, *, probe: ProbeFn | None = None, timeout: float = 10.0) -> None:
        self._probe = probe or _probe_ms17_010
        self._timeout = timeout

    async def run(
        self,
        target: "ScanTarget",
        creds: Any | None,
        ctx: "ScanContext",
    ) -> list[CVEResult]:
        del creds, ctx
        print_info_verbose(f"[ms17-010] probing {mark_sensitive(target.host, 'host')}")
        try:
            probe_result = await self._probe(host=target.host, timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_exception(exception=exc)
            print_error(f"[ms17-010] probe crashed against {target.host}: {exc}")
            return [_error(target.host, str(exc))]
        return [_result_from_probe(target.host, probe_result)]


def _base_kwargs(host: str) -> dict[str, Any]:
    return dict(
        cve_id=CVE_ID,
        aka=AKA,
        host=host,
        cvss_v3=CVSS_V3,
        cvss_vector=CVSS_VECTOR,
        severity=Severity.from_cvss(CVSS_V3),
    )


def _result_from_probe(host: str, probe: MS17ProbeResult) -> CVEResult:
    payload = {
        "nt_status": probe.nt_status,
        "summary": probe.summary,
        "error": probe.error,
    }
    if probe.not_applicable:
        return CVEResult(
            **_base_kwargs(host),
            status=CVEStatus.NOT_APPLICABLE,
            evidence=Evidence(summary=probe.summary, payload=payload),
        )
    if probe.error and probe.nt_status is None and not probe.vulnerable:
        return _error(host, probe.error or probe.summary)
    status = CVEStatus.VULNERABLE if probe.vulnerable else CVEStatus.NOT_VULNERABLE
    return CVEResult(
        **_base_kwargs(host),
        status=status,
        evidence=Evidence(summary=probe.summary, payload=payload),
    )


def _error(host: str, message: str) -> CVEResult:
    return CVEResult(
        **_base_kwargs(host),
        status=CVEStatus.ERROR,
        error=message,
        evidence=Evidence(summary=f"MS17-010 probe error: {message}", payload={}),
    )


__all__ = [
    "AKA",
    "CVE_ID",
    "CVSS_V3",
    "CVSS_VECTOR",
    "MS17ProbeResult",
    "MS17_010Check",
    "STATUS_INSUFF_SERVER_RESOURCES",
    "STATUS_NOT_SUPPORTED",
    "classify_status",
]
