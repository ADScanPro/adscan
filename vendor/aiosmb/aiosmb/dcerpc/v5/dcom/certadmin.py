#!/usr/bin/env python3
"""
ICertAdminD / ICertAdminD2 DCOM Interfaces for AD CS CA administration (MS-CSRA)

This module implements the AD CS CA-administration DCOM surface ADscan needs:

  - ``ICertAdminD2::GetCASecurity`` (opnum 36) — side-effect-free READ of the
    CA's authoritative security descriptor, used by the ADCS collector to
    recover DELEGATED ManageCA / ManageCertificates holders (the non-default
    holders that a CA object's LDAP ``nTSecurityDescriptor`` omits — they live
    only in the CA's own authoritative security descriptor).
  - ``ICertAdminD2::SetCASecurity`` (opnum 37) — WRITE of that security
    descriptor, used by ESC7 exploitation to grant/revoke ManageCA /
    ManageCertificates.
  - ``ICertAdminD::ResubmitRequest`` (opnum 5) — force-issue a pending/denied
    request, used by ESC7 to issue the SubCA request the CA held for approval.

All are Kerberos-native: activated from a ``DCOMConnection`` opened off an
existing SMB connection (``DCOMConnection.from_smbconnection``), so they reuse
that connection's GSSAPI/Kerberos context — no separate NTLM-only auth.

Based on:
    - [MS-CSRA] Certificate Services Remote Administration Protocol
    - [MS-WCCE] Windows Client Certificate Enrollment Protocol (CERTTRANSBLOB)

CLSID: {D99E6E73-FC88-11D0-B498-00A0C90312F3} - ICertAdmin
IID:   {7FE0D935-DDA6-443F-85D0-1CFB58FE41DD} - ICertAdminD2
IID:   {D99E6E71-FC88-11D0-B498-00A0C90312F3} - ICertAdminD
"""

from aiosmb import logger
from aiosmb.dcerpc.v5 import system_errors
from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown
from aiosmb.dcerpc.v5.dcom.dcomrt import DCOMCALL, DCOMANSWER
from aiosmb.dcerpc.v5.dtypes import DWORD, LONG, LPWSTR
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5.uuid import string_to_bin, uuidtup_to_bin

# Reuse the exact CERTTRANSBLOB NDR struct the ICertRequestD interface defines,
# so the NDR type registry sees ONE definition (no duplicate registration).
from aiosmb.dcerpc.v5.dcom.certreq import CERTTRANSBLOB


# =========================================================================
# Constants and Protocol UUIDs
# =========================================================================

# ICertAdmin CLSID - for DCOM activation (same CLSID impacket uses for D/D2)
CLSID_ICertAdmin = string_to_bin('D99E6E73-FC88-11D0-B498-00A0C90312F3')

# ICertAdminD2 Interface ID
IID_ICertAdminD2 = uuidtup_to_bin(('7FE0D935-DDA6-443F-85D0-1CFB58FE41DD', '0.0'))

# ICertAdminD (v1) — same activation CLSID, distinct IID. Hosts ResubmitRequest.
CLSID_ICertAdminD = string_to_bin('D99E6E73-FC88-11D0-B498-00A0C90312F3')
IID_ICertAdminD = uuidtup_to_bin(('D99E6E71-FC88-11D0-B498-00A0C90312F3', '0.0'))


class DCERPCSessionError(DCERPCException):
    """MS-CSRA session error mapping (parity with bkrp/fsrvp/atsvc).

    The DCE-RPC dispatcher (``dcerpc/v5/connection.py``) does
    ``getattr(module, 'DCERPCSessionError')`` on the interface's module to build
    a typed error when a returned status code is not in ``rpc_status_codes``.
    Without this class the dispatcher raised ``AttributeError`` and MASKED the
    real CSRA status the CA returned (observed against a live CA, 2026-07-24).
    """

    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'CSRA SessionError: code: 0x%x - %s - %s' % (
                self.error_code, error_msg_short, error_msg_verbose)
        return 'CSRA SessionError: unknown error code: 0x%x' % self.error_code


class CertAdminSecurityError(Exception):
    """Raised when ICertAdminD2::GetCASecurity fails at the DCERPC layer."""


# =========================================================================
# Protocol Structures for MS-CSRA GetCASecurity (opnum 36)
# =========================================================================

class ICertAdminD2GetCASecurity(DCOMCALL):
    """
    ICertAdminD2::GetCASecurity DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.2.6
    Opnum 36 - GetCASecurity method

    Reads the CA's authoritative security descriptor (the source of the CA's
    ManageCA / ManageCertificates holders).
    """
    opnum = 36
    structure = (
        ('pwszAuthority', LPWSTR),    # CA name (e.g., "DC01\\CA-Name")
    )


class ICertAdminD2GetCASecurityResponse(DCOMANSWER):
    """
    ICertAdminD2::GetCASecurity DCOM response structure.

    Defined in [MS-CSRA] section 3.1.4.2.6
    """
    structure = (
        ('pctbSD', CERTTRANSBLOB),    # Self-relative security-descriptor bytes
    )


# =========================================================================
# Protocol Structures for MS-CSRA SetCASecurity (opnum 37)
# =========================================================================

class ICertAdminD2SetCASecurity(DCOMCALL):
    """
    ICertAdminD2::SetCASecurity DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.2.7
    Opnum 37 - SetCASecurity method

    Writes the CA's authoritative security descriptor. Used by ESC7 to grant
    or revoke ManageCA / ManageCertificates for a principal.
    """
    opnum = 37
    structure = (
        ('pwszAuthority', LPWSTR),    # CA name (e.g., "DC01\\CA-Name")
        ('pctbSD', CERTTRANSBLOB),    # New self-relative security-descriptor bytes
    )


class ICertAdminD2SetCASecurityResponse(DCOMANSWER):
    """
    ICertAdminD2::SetCASecurity DCOM response structure.

    Defined in [MS-CSRA] section 3.1.4.2.7
    """
    structure = (
        ('ErrorCode', LONG),          # 0 = success
    )


# =========================================================================
# Protocol Structures for MS-CSRA ResubmitRequest (opnum 5, ICertAdminD)
# =========================================================================

class ICertAdminDResubmitRequest(DCOMCALL):
    """
    ICertAdminD::ResubmitRequest DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.1.4
    Opnum 5 - ResubmitRequest method

    On the ICertAdminD vtable: opnum 3 = SetExtension, opnum 4 = SetAttributes,
    opnum 5 = ResubmitRequest, opnum 6 = DenyRequest. Dispatching opnum 4 here
    calls SetAttributes on the request, which the CA rejects on a non-pending
    request with 0x80094003 CERTSRV_E_BAD_REQUESTSTATUS (observed on a live CA
    2026-07-24). Matches certipy's ICertAdminDResubmitRequest.opnum = 5.

    Re-submits (force-issues) a pending or denied request. Requires the
    ManageCertificates (officer) right. Used by ESC7 after the CA held the
    SubCA request for approval.
    """
    opnum = 5
    structure = (
        ('pwszAuthority', LPWSTR),      # CA name (e.g., "DC01\\CA-Name")
        ('pdwRequestId', DWORD),        # Request ID to resubmit
        ('pwszExtensionName', LPWSTR),  # Extension name (unused; null string)
    )


class ICertAdminDResubmitRequestResponse(DCOMANSWER):
    """
    ICertAdminD::ResubmitRequest DCOM response structure.

    Defined in [MS-CSRA] section 3.1.4.1.4
    """
    structure = (
        ('pdwDisposition', DWORD),      # CR_DISP_* (3 = issued, 0 = incomplete)
    )


# =========================================================================
# ICertAdminD2 DCOM Interface (GetCASecurity read + SetCASecurity write)
# =========================================================================

class ICertAdminD2(IRemUnknown):
    """
    ICertAdminD2 DCOM interface — GetCASecurity read for AD CS.

    Mirrors :class:`aiosmb.dcerpc.v5.dcom.certreq.ICertRequestD`: initialize
    from an activated interface, bind opnum calls via the inherited
    ``request`` machinery. Supports the async context manager for automatic
    ``RemRelease()``.

    Usage:
        async with DCOMConnection.from_smbconnection(smb_conn) as dcom:
            iInterface, err = await dcom.CoCreateInstanceEx(
                CLSID_ICertAdmin, IID_ICertAdminD2)
            async with ICertAdminD2(iInterface) as cert_admin:
                sd_bytes = await cert_admin.get_ca_security('DC01\\MyCA')
    """

    def __init__(self, interface):
        """
        Initialize ICertAdminD2 from an existing interface.

        Args:
            interface: INTERFACE instance from DCOM activation
        """
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertAdminD2

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self._released:
            try:
                await self.RemRelease()
            except Exception:
                # Don't mask the original exception
                pass
        return False

    async def get_ca_security(self, ca_name: str) -> bytes:
        """
        Read the CA's authoritative security descriptor (MS-CSRA GetCASecurity).

        Args:
            ca_name: CA name in format "hostname\\CA-Name"

        Returns:
            The raw self-relative security-descriptor bytes (``pctbSD``).

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure. The caller
                (the ADCS collector) decides whether to skip; this interface
                does NOT swallow the error.
        """
        req = ICertAdminD2GetCASecurity()
        req['pwszAuthority'] = ca_name + '\x00'

        logger.debug(f'Reading CA security descriptor via GetCASecurity: {ca_name}')

        # Direct opnum (36) call on the ACTIVATED ICertAdminD2 interface — the ORPC
        # target MUST be the interface's own IPID (get_iPid), NOT the IRemUnknown
        # IPID (get_ipidRemUnknown, which only exposes opnums 0-6). Dispatching a
        # high opnum against IRemUnknown yields RPC fault 0x800706D1
        # (RPC_S_PROCNUM_OUT_OF_RANGE). Mirrors impacket's `iface.get_iPid()` and
        # Certipy's `self.cert_admin2` dispatch. (IDispatch-based siblings like
        # shellwindows correctly pass ipidRemUnknown as a sub-interface ctor arg,
        # not as the method target — do not conflate the two.)
        resp, err = await self._request(req, IID_ICertAdminD2, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(f'GetCASecurity failed for {ca_name}: {err}') from err

        # pctbSD.pb is a PBYTE (pointer -> conformant byte array); aiosmb
        # auto-dereferences it to a Python list. Be robust to whether the NDR
        # char-array elements come back as 1-byte `bytes` (impacket-style) or as
        # ints, and to an already-flattened bytes/bytearray.
        raw_pb = resp['pctbSD']['pb']
        if isinstance(raw_pb, (bytes, bytearray)):
            sd_bytes = bytes(raw_pb)
        else:
            sd_bytes = b''.join(
                el if isinstance(el, (bytes, bytearray)) else bytes([el & 0xFF])
                for el in (raw_pb or [])
            )
        logger.info(f'Read CA security descriptor: {len(sd_bytes)} bytes for {ca_name}')
        return sd_bytes

    async def set_ca_security(self, ca_name: str, sd_bytes: bytes) -> int:
        """
        Write the CA's authoritative security descriptor (MS-CSRA SetCASecurity).

        Args:
            ca_name: CA name in format "hostname\\CA-Name"
            sd_bytes: The raw self-relative security-descriptor bytes to set.

        Returns:
            The CA's ``ErrorCode`` (0 = success).

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure.
        """
        req = ICertAdminD2SetCASecurity()
        req['pwszAuthority'] = ca_name + '\x00'
        # CERTTRANSBLOB.pb is a PBYTE (pointer -> conformant byte array). On the
        # SEND side a list of ints marshals correctly — same pattern as the CSR
        # blob in certreq.ICertRequestD.request (pctbRequest.pb = list(csr_der)).
        req['pctbSD']['cb'] = len(sd_bytes)
        req['pctbSD']['pb'] = list(sd_bytes)

        logger.debug(f'Writing CA security descriptor via SetCASecurity: {ca_name} ({len(sd_bytes)} bytes)')

        # Direct opnum (37) call on the ACTIVATED ICertAdminD2 interface — the ORPC
        # target MUST be the interface's own IPID (get_iPid), NOT the IRemUnknown
        # IPID (see get_ca_security for the 0x800706D1 rationale).
        resp, err = await self._request(req, IID_ICertAdminD2, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(f'SetCASecurity failed for {ca_name}: {err}') from err

        error_code = resp['ErrorCode']
        logger.info(f'SetCASecurity for {ca_name} returned ErrorCode={error_code}')
        return error_code

    async def _request(self, req, iid, uuid):
        """Internal DCOM request wrapper (parity with ICertRequestD)."""
        return await super().request(req, iid, uuid)


# =========================================================================
# ICertAdminD (v1) DCOM Interface (ResubmitRequest write)
# =========================================================================

class ICertAdminD(IRemUnknown):
    """
    ICertAdminD (v1) DCOM interface — ResubmitRequest.

    Same activation CLSID as ICertAdminD2 but a distinct IID; hosts the
    ResubmitRequest (opnum 5) ESC7 uses to force-issue a pending
    request. Mirrors :class:`ICertAdminD2` (activation, opnum dispatch via the
    interface's own IPID, async context manager for automatic ``RemRelease``).

    Usage:
        async with DCOMConnection.from_smbconnection(smb_conn) as dcom:
            iInterface, err = await dcom.CoCreateInstanceEx(
                CLSID_ICertAdminD, IID_ICertAdminD)
            async with ICertAdminD(iInterface) as cert_admin:
                disposition = await cert_admin.resubmit_request('DC01\\MyCA', 42)
    """

    def __init__(self, interface):
        """
        Initialize ICertAdminD from an existing interface.

        Args:
            interface: INTERFACE instance from DCOM activation
        """
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertAdminD

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self._released:
            try:
                await self.RemRelease()
            except Exception:
                # Don't mask the original exception
                pass
        return False

    async def resubmit_request(self, ca_name: str, request_id: int, ext_name: str = '\x00') -> int:
        """
        Force-issue a pending/denied request (MS-CSRA ResubmitRequest).

        Args:
            ca_name: CA name in format "hostname\\CA-Name"
            request_id: The pending request ID to resubmit.
            ext_name: Extension name (unused by ESC7; a null string).

        Returns:
            The disposition code (``pdwDisposition``; 3 = CR_DISP_ISSUED,
            0 = CR_DISP_INCOMPLETE).

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure.
        """
        req = ICertAdminDResubmitRequest()
        req['pwszAuthority'] = ca_name + '\x00'
        req['pdwRequestId'] = int(request_id)
        req['pwszExtensionName'] = ext_name

        logger.debug(f'Resubmitting request {request_id} via ResubmitRequest: {ca_name}')

        # Direct opnum (4) call on the ACTIVATED ICertAdminD interface — dispatch
        # against the interface's own IPID (get_iPid), same as ICertAdminD2.
        resp, err = await self._request(req, IID_ICertAdminD, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(f'ResubmitRequest failed for {ca_name} (id={request_id}): {err}') from err

        disposition = resp['pdwDisposition']
        logger.info(f'ResubmitRequest for {ca_name} id={request_id} returned disposition={disposition}')
        return disposition

    async def _request(self, req, iid, uuid):
        """Internal DCOM request wrapper (parity with ICertAdminD2)."""
        return await super().request(req, iid, uuid)
