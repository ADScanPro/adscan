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
  - ``ICertAdminD2::GetMyRoles`` (opnum 47), ``GetOfficerRights`` (opnum 42) and
    ``GetCAProperty`` (opnum 32, read with ``CR_PROP_ROLESEPARATIONENABLED``;
    the answer is ``CAINFO.lRoleSeparationEnabled``, MS-WCCE 3.2.1.4.3.2.23) —
    side-effect-free READS that establish, BEFORE a certificate is requested,
    whether the caller can revoke it on this CA (the officer bit, officer-rights
    restrictions, role separation). All three need only Read on the CA, which
    Enroll implies.

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
from aiosmb.dcerpc.v5.dtypes import BOOL, DWORD, FILETIME, LONG, LPWSTR
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


def _dcerpc_error_code(err) -> int | None:
    """Best-effort recover the numeric fault / NT-status code from a DCE-RPC error.

    The DCE-RPC / DCOM error objects (``DCERPCException`` and its subclasses,
    including this module's ``DCERPCSessionError``) carry the fault code on
    ``error_code`` and expose ``get_error_code()``. A plain transport exception
    carries neither. Returns the code as an ``int`` when available, else ``None``.
    """
    if err is None:
        return None
    code = getattr(err, 'error_code', None)
    if code is None:
        getter = getattr(err, 'get_error_code', None)
        if callable(getter):
            try:
                code = getter()
            except Exception:
                code = None
    if isinstance(code, int):
        return code
    return None


def _describe_dcerpc_error(err) -> str:
    """Return a NON-EMPTY, human-usable description of a DCE-RPC / DCOM error.

    The inner DCE-RPC error for some DCOM faults stringifies to an EMPTY string
    (e.g. a session-error subclass built with ``error_code=None`` even raises in
    its own ``__str__``), which produced the ``... failed for <CA>:`` bare-colon
    message with no cause. This guarantees a cause token: the fault/NT-status
    code when the error carries one (``0x...``), otherwise the string form, and
    ``repr(err)`` as the final fallback — so the wrapper message is never empty
    and always classifiable by code.
    """
    code = _dcerpc_error_code(err)
    text = ''
    try:
        text = str(err)
    except Exception:
        # A malformed error object whose __str__ raises (e.g. error_code=None in
        # a %x format). Fall back to repr / the recovered code below.
        text = ''
    text = (text or '').strip()
    if code is not None:
        code_token = f'0x{code & 0xffffffff:08x}'
        if text and code_token.lower() not in text.lower():
            return f'{text} ({code_token})'
        if text:
            return text
        return code_token
    if text:
        return text
    return repr(err)


class CertAdminSecurityError(Exception):
    """Raised when an ICertAdminD2 / ICertAdminD call fails at the DCERPC layer.

    Carries the underlying DCE-RPC / DCOM fault code on ``error_code`` (an
    ``int`` HRESULT / NT-status such as ``0x80070005`` ACCESS_DENIED, or ``None``
    when the inner error exposes no code) so a caller can classify the failure by
    CODE — an EXPECTED not-CA-admin ACCESS_DENIED versus a real transport/RPC
    fault — without substring-matching a message that may stringify empty.
    """

    def __init__(self, message: str, error_code: int | None = None):
        super().__init__(message)
        self.error_code = error_code


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
# Protocol Structures for MS-CSRA RevokeCertificate (opnum 10, ICertAdminD)
# =========================================================================

#: CRL reason codes (RFC 5280 5.3.1) accepted by RevokeCertificate.
CRL_REASON_UNSPECIFIED = 0
CRL_REASON_KEY_COMPROMISE = 1


#: IsValidCertificate dispositions (certadm.h CA_DISP_*).
CA_DISP_REVOKED = 2
CA_DISP_VALID = 3


class ICertAdminDIsValidCertificate(DCOMCALL):
    """
    ICertAdminD::IsValidCertificate DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.1.5. Opnum 7. Reads a certificate's
    status from the CA database; used to CONFIRM a revocation by re-reading.
    """
    opnum = 7
    structure = (
        ('pwszAuthority', LPWSTR),
        ('pSerialNumber', LPWSTR),
    )


class ICertAdminDIsValidCertificateResponse(DCOMANSWER):
    """ICertAdminD::IsValidCertificate response: reason, disposition, HRESULT."""
    structure = (
        ('pRevocationReason', LONG),
        ('pDisposition', LONG),
        ('ErrorCode', LONG),
    )


class ICertAdminDRevokeCertificate(DCOMCALL):
    """
    ICertAdminD::RevokeCertificate DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.1.8.
    Opnum 10 on the ICertAdminD vtable (3 SetExtension, 4 SetAttributes,
    5 ResubmitRequest, 6 DenyRequest, 7 IsValidCertificate, 8 PublishCRL,
    9 GetCRL, 10 RevokeCertificate).

    Revokes an issued certificate by serial number. Requires the
    ManageCertificates (officer) right on the CA. A FileTime of zero revokes
    it as of now. The revocation reaches relying parties once the CA
    publishes its next CRL.
    """
    opnum = 10
    structure = (
        ('pwszAuthority', LPWSTR),      # CA name (e.g., "CORP-CA")
        ('pwszSerialNumber', LPWSTR),   # Hex serial as the CA database stores it
        ('Reason', DWORD),              # CRL_REASON_*
        ('FileTime', FILETIME),         # 0 = revoke now
    )


class ICertAdminDRevokeCertificateResponse(DCOMANSWER):
    """
    ICertAdminD::RevokeCertificate DCOM response structure (HRESULT only).
    """
    structure = (
        ('ErrorCode', LONG),
    )


# =========================================================================
# Reversal-capability reads (MS-CSRA GetMyRoles / GetOfficerRights /
# GetCAProperty) — all three need only Read on the CA
# =========================================================================

#: CA access bits ([MS-CSRA] 3.1.1.7; certadm.h CA_ACCESS_*). GetMyRoles returns
#: the CALLER's own roles over these bits; the CA evaluates nested and
#: cross-domain group membership itself.
CA_ACCESS_ADMIN = 0x00000001     # Manage CA (also needed to publish a CRL)
CA_ACCESS_OFFICER = 0x00000002   # Issue and Manage Certificates (revoke)
CA_ACCESS_AUDITOR = 0x00000004
CA_ACCESS_OPERATOR = 0x00000008
CA_ACCESS_READ = 0x00000100
CA_ACCESS_ENROLL = 0x00000200

#: [MS-WCCE] 3.2.1.4.3.2.23: CR_PROP_ROLESEPARATIONENABLED (PropID 23 = 0x17),
#: requested with PROPTYPE_LONG (1). The CA does NOT answer with a bare LONG: it
#: MUST return "the value through the lRoleSeparationEnabled field of a CAINFO
#: (section 2.2.2.4) structure", carried in the CERTTRANSBLOB. Reading the first
#: DWORD of the blob reads CAINFO.cbSize (40 on a current CA), never the flag.
CR_PROP_ROLESEPARATIONENABLED = 0x17
PROPTYPE_LONG = 0x1

#: [MS-WCCE] 2.2.2.4 CAINFO, ten 4-byte little-endian fields in this order:
#: cbSize, CAType, cCASignatureCerts, cCAExchangeCerts, cExitAlgorithms,
#: lPropIDMax, lRoleSeparationEnabled, cKRACertUsedCount, cKRACertCount,
#: fAdvancedServer. ``lRoleSeparationEnabled`` is the seventh field.
CAINFO_ROLE_SEPARATION_OFFSET = 24
CAINFO_MIN_SIZE_FOR_ROLE_SEPARATION = CAINFO_ROLE_SEPARATION_OFFSET + 4


def parse_cainfo_role_separation(blob: bytes) -> int:
    """``CAINFO.lRoleSeparationEnabled`` from a GetCAProperty(0x17) value blob.

    The CA MUST return 0 (disabled) or 1 (enabled); the raw value is returned
    unchanged so the caller decides what an unexpected value means (never "on").

    Raises:
        CertAdminSecurityError: the blob is too short to carry the field, or its
            own ``cbSize`` says the structure ends before it.
    """
    data = bytes(blob or b'')
    if len(data) < CAINFO_MIN_SIZE_FOR_ROLE_SEPARATION:
        raise CertAdminSecurityError(
            f'GetCAProperty(role separation) returned {len(data)} bytes, '
            f'not a CAINFO structure carrying lRoleSeparationEnabled'
        )
    cb_size = int.from_bytes(data[0:4], 'little', signed=False)
    if cb_size < CAINFO_MIN_SIZE_FOR_ROLE_SEPARATION:
        raise CertAdminSecurityError(
            f'GetCAProperty(role separation) returned a CAINFO of cbSize={cb_size}, '
            f'too small to carry lRoleSeparationEnabled'
        )
    off = CAINFO_ROLE_SEPARATION_OFFSET
    return int.from_bytes(data[off:off + 4], 'little', signed=True)


class ICertAdminD2GetMyRoles(DCOMCALL):
    """
    ICertAdminD2::GetMyRoles DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.2.16. Opnum 47 on the ICertAdminD2
    vtable (... 42 GetOfficerRights, 43 SetOfficerRights, 44 GetConfigEntry,
    45 SetConfigEntry, 46 ImportKey, 47 GetMyRoles, 48 DeleteRow).

    Returns the caller's own CA roles (CA_ACCESS_* bits). Requires only Read.
    """
    opnum = 47
    structure = (
        ('pwszAuthority', LPWSTR),
    )


class ICertAdminD2GetMyRolesResponse(DCOMANSWER):
    """ICertAdminD2::GetMyRoles response: the caller's role bits and the HRESULT."""
    structure = (
        ('pdwRoles', LONG),
        ('ErrorCode', LONG),
    )


class ICertAdminD2GetOfficerRights(DCOMCALL):
    """
    ICertAdminD2::GetOfficerRights DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.2.11. Opnum 42.

    ``pfEnabled`` 0 means officer rights are unrestricted (the CA security
    descriptor is the whole story); non-zero means a restriction list scopes
    which subjects a Certificate Manager may act on, a second access check the
    roles do not reflect. Requires only Read.
    """
    opnum = 42
    structure = (
        ('pwszAuthority', LPWSTR),
    )


class ICertAdminD2GetOfficerRightsResponse(DCOMANSWER):
    """ICertAdminD2::GetOfficerRights response."""
    structure = (
        ('pfEnabled', BOOL),
        ('pctbSD', CERTTRANSBLOB),
        ('ErrorCode', LONG),
    )


class ICertAdminD2GetCAProperty(DCOMCALL):
    """
    ICertAdminD2::GetCAProperty DCOM call structure.

    Defined in [MS-CSRA] section 3.1.4.2.2. Opnum 32 (31 PublishCRLs,
    32 GetCAProperty, 33 SetCAProperty). Used with
    ``CR_PROP_ROLESEPARATIONENABLED``. Requires only Read.
    """
    opnum = 32
    structure = (
        ('pwszAuthority', LPWSTR),
        ('PropId', LONG),
        ('PropIndex', LONG),
        ('PropType', LONG),
    )


class ICertAdminD2GetCAPropertyResponse(DCOMANSWER):
    """ICertAdminD2::GetCAProperty response: the value blob and the HRESULT."""
    structure = (
        ('pctbPropertyValue', CERTTRANSBLOB),
        ('ErrorCode', LONG),
    )


def _blob_bytes(raw_pb) -> bytes:
    """Flatten a CERTTRANSBLOB ``pb`` (list of ints / 1-byte bytes / bytes) to bytes."""
    if raw_pb is None:
        return b''
    if isinstance(raw_pb, (bytes, bytearray)):
        return bytes(raw_pb)
    return b''.join(
        el if isinstance(el, (bytes, bytearray)) else bytes([el & 0xFF])
        for el in (raw_pb or [])
    )


def _check_hresult(resp, what: str, ca_name: str) -> None:
    """Raise when the response carries a failing HRESULT (never read it as data)."""
    try:
        code = int(resp['ErrorCode'])
    except Exception:
        return
    if code:
        raise CertAdminSecurityError(
            f'{what} failed for {ca_name}: HRESULT 0x{code & 0xffffffff:08x}',
            error_code=code & 0xffffffff,
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
        # certsrv refuses anything below an encrypted binding (Certipy parity).
        self.require_packet_privacy()

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
            raise CertAdminSecurityError(
                f'GetCASecurity failed for {ca_name}: {_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err

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
            raise CertAdminSecurityError(
                f'SetCASecurity failed for {ca_name}: {_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err

        error_code = resp['ErrorCode']
        logger.info(f'SetCASecurity for {ca_name} returned ErrorCode={error_code}')
        return error_code

    async def get_my_roles(self, ca_name: str) -> int:
        """
        Read the caller's own CA roles (MS-CSRA GetMyRoles, opnum 47).

        Returns:
            The CA_ACCESS_* bitmask the CA evaluated for the caller.

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure or failing HRESULT.
        """
        req = ICertAdminD2GetMyRoles()
        req['pwszAuthority'] = ca_name + '\x00'
        resp, err = await self._request(req, IID_ICertAdminD2, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(
                f'GetMyRoles failed for {ca_name}: {_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err
        _check_hresult(resp, 'GetMyRoles', ca_name)
        roles = int(resp['pdwRoles']) & 0xffffffff
        logger.debug(f'GetMyRoles for {ca_name} returned 0x{roles:08x}')
        return roles

    async def get_officer_rights(self, ca_name: str) -> tuple:
        """
        Read whether officer rights are restricted (MS-CSRA GetOfficerRights, opnum 42).

        Returns:
            ``(enabled, sd_bytes)``: ``enabled`` False means unrestricted; when
            True, ``sd_bytes`` is the restriction security descriptor.

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure or failing HRESULT.
        """
        req = ICertAdminD2GetOfficerRights()
        req['pwszAuthority'] = ca_name + '\x00'
        resp, err = await self._request(req, IID_ICertAdminD2, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(
                f'GetOfficerRights failed for {ca_name}: {_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err
        _check_hresult(resp, 'GetOfficerRights', ca_name)
        enabled = bool(int(resp['pfEnabled']))
        sd_bytes = _blob_bytes(resp['pctbSD']['pb']) if enabled else b''
        return enabled, sd_bytes

    async def _get_ca_property_blob(
        self, ca_name: str, prop_id: int, prop_type: int, prop_index: int = 0
    ) -> bytes:
        """The raw ``pctbPropertyValue`` blob of MS-CSRA GetCAProperty (opnum 32)."""
        req = ICertAdminD2GetCAProperty()
        req['pwszAuthority'] = ca_name + '\x00'
        req['PropId'] = int(prop_id)
        req['PropIndex'] = int(prop_index)
        req['PropType'] = int(prop_type)
        resp, err = await self._request(req, IID_ICertAdminD2, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(
                f'GetCAProperty failed for {ca_name}: {_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err
        _check_hresult(resp, 'GetCAProperty', ca_name)
        return _blob_bytes(resp['pctbPropertyValue']['pb'])

    async def get_role_separation_enabled(self, ca_name: str) -> int:
        """
        Read whether role separation is enforced on the CA (``CAINFO.lRoleSeparationEnabled``).

        [MS-WCCE] 3.2.1.4.3.2.23: GetCAProperty(CR_PROP_ROLESEPARATIONENABLED,
        PROPTYPE_LONG) carries the answer inside a CAINFO structure (2.2.2.4),
        not as a bare LONG. Requires only Read.

        Returns:
            The field as the CA sent it (0 = off, 1 = on).

        Raises:
            CertAdminSecurityError: on a DCERPC failure, failing HRESULT, or a
                blob that does not carry the field.
        """
        blob = await self._get_ca_property_blob(
            ca_name, CR_PROP_ROLESEPARATIONENABLED, PROPTYPE_LONG
        )
        value = parse_cainfo_role_separation(blob)
        logger.debug(f'GetCAProperty(role separation) for {ca_name} returned {value}')
        return value

    async def get_ca_property_long(self, ca_name: str, prop_id: int, prop_index: int = 0) -> int:
        """
        Read a LONG CA property returned as a bare LONG (MS-CSRA GetCAProperty, opnum 32).

        NOT for the properties [MS-WCCE] 3.2.1.4.3.2 returns inside a CAINFO
        structure (role separation, CA type, certificate counts, advanced
        server): their first DWORD is ``CAINFO.cbSize``. Role separation is read
        with :meth:`get_role_separation_enabled`.

        Raises:
            CertAdminSecurityError: on a DCERPC failure, failing HRESULT, or a
                value blob that is not a 4-byte LONG.
        """
        req = ICertAdminD2GetCAProperty()
        req['pwszAuthority'] = ca_name + '\x00'
        req['PropId'] = int(prop_id)
        req['PropIndex'] = int(prop_index)
        req['PropType'] = PROPTYPE_LONG
        resp, err = await self._request(req, IID_ICertAdminD2, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(
                f'GetCAProperty failed for {ca_name}: {_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err
        _check_hresult(resp, 'GetCAProperty', ca_name)
        value = _blob_bytes(resp['pctbPropertyValue']['pb'])
        if len(value) < 4:
            raise CertAdminSecurityError(
                f'GetCAProperty for {ca_name} returned {len(value)} bytes, not a LONG',
            )
        return int.from_bytes(value[:4], 'little', signed=True)

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
        # certsrv refuses anything below an encrypted binding (Certipy parity).
        self.require_packet_privacy()

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
            raise CertAdminSecurityError(
                f'ResubmitRequest failed for {ca_name} (id={request_id}): '
                f'{_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err

        disposition = resp['pdwDisposition']
        logger.info(f'ResubmitRequest for {ca_name} id={request_id} returned disposition={disposition}')
        return disposition

    async def certificate_disposition(self, ca_name: str, serial_number: str) -> int:
        """
        Read a certificate's CA-database status (MS-CSRA IsValidCertificate).

        Returns:
            ``pDisposition`` (CA_DISP_REVOKED = 2, CA_DISP_VALID = 3, ...).

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure.
        """
        req = ICertAdminDIsValidCertificate()
        req['pwszAuthority'] = ca_name + '\x00'
        req['pSerialNumber'] = str(serial_number).replace(' ', '').replace(':', '') + '\x00'
        resp, err = await self._request(req, IID_ICertAdminD, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(
                f'IsValidCertificate failed for {ca_name} (serial={serial_number}): '
                f'{_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err
        return int(resp['pDisposition'])

    async def revoke_certificate(
        self, ca_name: str, serial_number: str, reason: int = CRL_REASON_KEY_COMPROMISE
    ) -> int:
        """
        Revoke an issued certificate by serial (MS-CSRA RevokeCertificate).

        Args:
            ca_name: CA name (e.g. "CORP-CA").
            serial_number: Hex serial number, no separators.
            reason: CRL reason code (default: key compromise).

        Returns:
            The CA's ``ErrorCode`` (0 = revoked).

        Raises:
            CertAdminSecurityError: on any DCERPC-layer failure (for example
                access denied when the caller is not a certificate manager).
        """
        req = ICertAdminDRevokeCertificate()
        req['pwszAuthority'] = ca_name + '\x00'
        req['pwszSerialNumber'] = str(serial_number).replace(' ', '').replace(':', '') + '\x00'
        req['Reason'] = int(reason)
        req['FileTime']['dwLowDateTime'] = 0
        req['FileTime']['dwHighDateTime'] = 0

        logger.debug(f'Revoking certificate {serial_number} via RevokeCertificate: {ca_name}')

        resp, err = await self._request(req, IID_ICertAdminD, self.get_iPid())
        if err is not None:
            raise CertAdminSecurityError(
                f'RevokeCertificate failed for {ca_name} (serial={serial_number}): '
                f'{_describe_dcerpc_error(err)}',
                error_code=_dcerpc_error_code(err),
            ) from err
        error_code = resp['ErrorCode']
        logger.info(f'RevokeCertificate for {ca_name} serial={serial_number} returned ErrorCode={error_code}')
        return error_code

    async def _request(self, req, iid, uuid):
        """Internal DCOM request wrapper (parity with ICertAdminD2)."""
        return await super().request(req, iid, uuid)
