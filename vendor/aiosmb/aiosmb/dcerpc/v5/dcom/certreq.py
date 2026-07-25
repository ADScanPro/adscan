#!/usr/bin/env python3
"""
ICertRequestD DCOM Interface for AD CS Certificate Management

This module implements the ICertRequestD DCOM interface for interacting with
Active Directory Certificate Services (AD CS).

Based on:
    - [MS-WCCE] Windows Client Certificate Enrollment Protocol
    - [MS-ICPR] ICertPassage Remote Protocol

Reference implementation: Certipy by ly4k
https://github.com/ly4k/Certipy

CLSID: {D99E6E74-FC88-11D0-B498-00A0C90312F3} - ICertRequest
IID:   {D99E6E70-FC88-11D0-B498-00A0C90312F3} - ICertRequestD
"""

from aiosmb import logger
from aiosmb.dcerpc.v5.dcom.remunknown import IRemUnknown
from aiosmb.dcerpc.v5.dcom.interface import INTERFACE
from aiosmb.dcerpc.v5.dcom.dcomrt import DCOMCALL, DCOMANSWER
from aiosmb.dcerpc.v5.ndr import NDRSTRUCT, NDRPOINTER, NDRUniConformantArray
from aiosmb.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, LONG, PBYTE
from aiosmb.dcerpc.v5.uuid import string_to_bin, uuidtup_to_bin


# =========================================================================
# Constants and Protocol UUIDs
# =========================================================================

# ICertRequest CLSID - for DCOM activation
CLSID_ICertRequest = string_to_bin('D99E6E74-FC88-11D0-B498-00A0C90312F3')

# ICertRequestD Interface ID
IID_ICertRequestD = uuidtup_to_bin(('D99E6E70-FC88-11D0-B498-00A0C90312F3', '0.0'))

# Certificate disposition codes (MS-WCCE 3.2.1.4.2.1.4)
CR_DISP_INCOMPLETE = 0
CR_DISP_ERROR = 1
CR_DISP_DENIED = 2
CR_DISP_ISSUED = 3
CR_DISP_ISSUED_OUT_OF_BAND = 4
CR_DISP_UNDER_SUBMISSION = 5
CR_DISP_REVOKED = 6

# Friendly names for disposition codes
DISPOSITION_NAMES = {
    CR_DISP_INCOMPLETE: 'Incomplete',
    CR_DISP_ERROR: 'Error',
    CR_DISP_DENIED: 'Denied',
    CR_DISP_ISSUED: 'Issued',
    CR_DISP_ISSUED_OUT_OF_BAND: 'Issued (out of band)',
    CR_DISP_UNDER_SUBMISSION: 'Pending',
    CR_DISP_REVOKED: 'Revoked',
}

# Request flags (MS-WCCE 3.2.1.4.2.1.1)
CR_IN_BASE64HEADER = 0x00000000
CR_IN_BASE64 = 0x00000001
CR_IN_BINARY = 0x00000002
CR_IN_ENCODEANY = 0x000000ff
CR_IN_PKCS10 = 0x00000100
CR_IN_KEYGEN = 0x00000200
CR_IN_PKCS7 = 0x00000300
CR_IN_CMC = 0x00000400
CR_IN_RPC = 0x00020000


# =========================================================================
# Protocol Structures for MS-WCCE
# =========================================================================

class BYTE_ARRAY(NDRUniConformantArray):
    """Conformant array of bytes"""
    item = 'c'


class CERTTRANSBLOB(NDRSTRUCT):
    """
    Certificate transport blob structure.
    
    Defined in [MS-WCCE] section 2.2.2.2
    Used to transport certificate data and request attributes.
    """
    structure = (
        ('cb', ULONG),      # Size of the pb field in bytes
        # [MS-WCCE] 2.2.2.2: pb is `[size_is(cb)] BYTE *pb` — a POINTER to a
        # conformant byte array, NOT an inline array. Modelling it as a bare
        # NDRUniConformantArray (BYTE_ARRAY) omits the NDR referent, misaligning
        # the unmarshaled bytes so `b''.join(resp['pctbSD']['pb'])` yields empty/
        # garbage (GetCASecurity parsed 0 ACEs against a live CA, 2026-07-24).
        # PBYTE (= LPBYTE: NDRPOINTER -> NDRUniConformantArray) matches impacket's
        # CERTTRANSBLOB and Certipy exactly.
        ('pb', PBYTE),      # Data bytes (pointer to conformant array)
    )


class PCERTTRANSBLOB(NDRPOINTER):
    """Pointer to CERTTRANSBLOB"""
    referent = (
        ('Data', CERTTRANSBLOB),
    )


class CertServerRequestD(DCOMCALL):
    """
    ICertRequestD::Request DCOM call structure.
    
    Defined in [MS-WCCE] section 3.2.1.4.3.1
    Opnum 3 - Request method
    
    This is the main method for submitting certificate requests
    to Active Directory Certificate Services.
    """
    opnum = 3
    structure = (
        ('dwFlags', DWORD),           # Request format flags (CR_IN_*)
        ('pwszAuthority', LPWSTR),    # CA name (e.g., "DC01\\CA-Name")
        ('pdwRequestId', DWORD),      # Request ID (0 for new requests)
        ('pwszAttributes', LPWSTR),   # Request attributes string
        ('pctbRequest', CERTTRANSBLOB),  # Certificate request data (CSR)
    )


class CertServerRequestDResponse(DCOMANSWER):
    """
    ICertRequestD::Request DCOM response structure.
    
    Defined in [MS-WCCE] section 3.2.1.4.3.1
    """
    structure = (
        ('pdwRequestId', DWORD),              # Assigned request ID
        ('pdwDisposition', ULONG),            # Request disposition (CR_DISP_*)
        ('pctbCertChain', CERTTRANSBLOB),     # Certificate chain (PKCS#7)
        ('pctbEncodedCert', CERTTRANSBLOB),   # DER-encoded certificate
        ('pctbDispositionMessage', CERTTRANSBLOB),  # Disposition message
    )


class GetCACert(DCOMCALL):
    """
    ICertRequestD::GetCACert DCOM call structure.
    
    Defined in [MS-WCCE] section 3.2.1.4.3.2
    Opnum 4 - GetCACert method
    
    Retrieves the CA certificate or other CA-related data.
    """
    opnum = 4
    structure = (
        ('fchain', DWORD),             # Type of data to retrieve
        ('pwszAuthority', LPWSTR),     # CA name
    )


class GetCACertResponse(DCOMANSWER):
    """
    ICertRequestD::GetCACert DCOM response structure.
    
    Defined in [MS-WCCE] section 3.2.1.4.3.2
    """
    structure = (
        ('pctbOut', CERTTRANSBLOB),    # Requested CA data
    )


# =========================================================================
# ICertRequestD DCOM Interface
# =========================================================================

class ICertRequestD(IRemUnknown):
    """
    ICertRequestD DCOM interface implementation for AD CS.
    
    This interface provides methods to:
    - Submit certificate requests to a Certificate Authority
    - Retrieve pending certificates by request ID
    - Get CA certificate information
    
    Note: This interface does NOT provide a method to enumerate available CAs.
    CA discovery must be done via LDAP queries to Active Directory, searching
    for pKIEnrollmentService objects in the Configuration naming context.
    
    Supports async context manager for automatic resource cleanup:
        async with ICertRequestD(iInterface) as cert_req:
            result, err = await cert_req.request(...)
        # RemRelease() called automatically
    
    Usage:
        # After DCOM activation with CLSID_ICertRequest
        async with ICertRequestD(iInterface) as cert_req:
            # Submit a certificate request
            result, err = await cert_req.request(
                ca_name='DC01\\MyCA',
                csr_der=csr_bytes,
                attributes=['CertificateTemplate:User']
            )
            
            # Retrieve a pending certificate
            result, err = await cert_req.retrieve(
                ca_name='DC01\\MyCA', 
                request_id=123
            )
    """
    
    def __init__(self, interface):
        """
        Initialize ICertRequestD from an existing interface.
        
        Args:
            interface: INTERFACE instance from DCOM activation
        """
        IRemUnknown.__init__(self, interface)
        self._iid = IID_ICertRequestD
    
    async def __aenter__(self):
        """
        Async context manager entry.
        
        Returns:
            self for use in 'async with' statements
        """
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Async context manager exit.
        
        Automatically calls RemRelease() to clean up the interface.
        Exceptions during release are silently ignored to avoid
        masking the original exception (if any).
        
        Returns:
            False - don't suppress exceptions
        """
        if not self._released:
            try:
                await self.RemRelease()
            except Exception:
                # Don't mask the original exception
                pass
        return False
    
    async def request(
        self,
        ca_name: str,
        csr_der: bytes,
        attributes: list = None,
        flags: int = CR_IN_BINARY | CR_IN_PKCS10
    ):
        """
        Submit a certificate request to the CA.
        
        Args:
            ca_name: CA name in format "hostname\\CA-Name"
            csr_der: DER-encoded certificate signing request (CSR)
            attributes: List of request attributes (e.g., ['CertificateTemplate:User'])
            flags: Request flags (default: binary PKCS10)
        
        Returns:
            (result_dict, None) on success where result_dict contains:
                - 'request_id': The assigned request ID
                - 'disposition': Disposition code (CR_DISP_*)
                - 'disposition_name': Human-readable disposition
                - 'certificate': DER-encoded certificate (if issued)
                - 'certificate_chain': PKCS#7 certificate chain (if issued)
                - 'disposition_message': Error/status message
            
            (None, Exception) on failure
        """
        try:
            # Build attributes string
            attributes_str = '\n'.join(attributes) if attributes else ''
            
            # Build request structure
            req = CertServerRequestD()
            req['dwFlags'] = flags
            req['pwszAuthority'] = ca_name + '\x00'
            req['pdwRequestId'] = 0  # New request
            req['pwszAttributes'] = attributes_str + '\x00' if attributes_str else '\x00'
            
            # Set CSR data
            req['pctbRequest']['cb'] = len(csr_der)
            req['pctbRequest']['pb'] = list(csr_der)
            
            logger.debug(f'Submitting certificate request to CA: {ca_name}')
            logger.debug(f'Attributes: {attributes_str}')
            logger.debug(f'CSR size: {len(csr_der)} bytes')
            
            # Send request
            # Direct opnum call on the ACTIVATED ICertRequestD interface — target the
            # interface's own IPID (get_iPid), NOT the IRemUnknown IPID (opnums 0-6);
            # a direct opnum vs get_ipidRemUnknown yields RPC fault 0x800706D1. Same
            # bug/fix as certadmin.py; mirrors impacket's `iface.get_iPid()`.
            resp, err = await self._request(req, IID_ICertRequestD, self.get_iPid())
            if err is not None:
                raise err
            
            # Parse response
            request_id = resp['pdwRequestId']
            disposition = resp['pdwDisposition']
            disposition_name = DISPOSITION_NAMES.get(disposition, f'Unknown ({disposition})')
            
            # Extract certificate if issued
            certificate = None
            certificate_chain = None
            
            if disposition == CR_DISP_ISSUED:
                cert_data = b''.join(resp['pctbEncodedCert']['pb'])
                if len(cert_data) > 0:
                    certificate = cert_data
                
                chain_data = b''.join(resp['pctbCertChain']['pb'])
                if len(chain_data) > 0:
                    certificate_chain = chain_data
            
            # Extract disposition message
            disposition_message = None
            msg_data = b''.join(resp['pctbDispositionMessage']['pb'])
            if len(msg_data) > 0:
                try:
                    disposition_message = msg_data.decode('utf-16-le').rstrip('\x00')
                except Exception:
                    disposition_message = msg_data
            
            result = {
                'request_id': request_id,
                'disposition': disposition,
                'disposition_name': disposition_name,
                'certificate': certificate,
                'certificate_chain': certificate_chain,
                'disposition_message': disposition_message,
            }
            
            logger.info(f'Certificate request submitted: ID={request_id}, Status={disposition_name}')
            
            return result, None
            
        except Exception as e:
            logger.error(f'Certificate request failed: {e}')
            return None, e
    
    async def retrieve(
        self,
        ca_name: str,
        request_id: int,
        flags: int = CR_IN_BINARY | CR_IN_PKCS10
    ):
        """
        Retrieve a pending certificate by request ID.
        
        Args:
            ca_name: CA name in format "hostname\\CA-Name"
            request_id: The request ID from a previous submission
            flags: Request flags (default: binary PKCS10)
        
        Returns:
            (result_dict, None) on success where result_dict contains:
                - 'request_id': The request ID
                - 'disposition': Disposition code (CR_DISP_*)
                - 'disposition_name': Human-readable disposition
                - 'certificate': DER-encoded certificate (if issued)
                - 'certificate_chain': PKCS#7 certificate chain (if issued)
                - 'disposition_message': Error/status message
            
            (None, Exception) on failure
        """
        try:
            # Build request structure - same as request but with existing ID
            req = CertServerRequestD()
            req['dwFlags'] = flags
            req['pwszAuthority'] = ca_name + '\x00'
            req['pdwRequestId'] = request_id
            req['pwszAttributes'] = '\x00'
            
            # Empty CSR for retrieval
            req['pctbRequest']['cb'] = 0
            req['pctbRequest']['pb'] = []
            
            logger.debug(f'Retrieving certificate from CA: {ca_name}, Request ID: {request_id}')
            
            # Send request
            # Direct opnum call on the ACTIVATED ICertRequestD interface — target the
            # interface's own IPID (get_iPid), NOT the IRemUnknown IPID (opnums 0-6);
            # a direct opnum vs get_ipidRemUnknown yields RPC fault 0x800706D1. Same
            # bug/fix as certadmin.py; mirrors impacket's `iface.get_iPid()`.
            resp, err = await self._request(req, IID_ICertRequestD, self.get_iPid())
            if err is not None:
                raise err
            
            # Parse response
            disposition = resp['pdwDisposition']
            disposition_name = DISPOSITION_NAMES.get(disposition, f'Unknown ({disposition})')
            
            # Extract certificate if issued
            certificate = None
            certificate_chain = None
            
            if disposition == CR_DISP_ISSUED:
                cert_data = b''.join(resp['pctbEncodedCert']['pb'])
                if len(cert_data) > 0:
                    certificate = cert_data
                
                chain_data = b''.join(resp['pctbCertChain']['pb'])
                if len(chain_data) > 0:
                    certificate_chain = chain_data
            
            # Extract disposition message
            disposition_message = None
            msg_data = b''.join(resp['pctbDispositionMessage']['pb'])
            if len(msg_data) > 0:
                try:
                    disposition_message = msg_data.decode('utf-16-le').rstrip('\x00')
                except Exception:
                    disposition_message = msg_data
            
            result = {
                'request_id': request_id,
                'disposition': disposition,
                'disposition_name': disposition_name,
                'certificate': certificate,
                'certificate_chain': certificate_chain,
                'disposition_message': disposition_message,
            }
            
            logger.info(f'Certificate retrieval: ID={request_id}, Status={disposition_name}')
            
            return result, None
            
        except Exception as e:
            logger.error(f'Certificate retrieval failed: {e}')
            return None, e
    
    async def get_ca_cert(self, ca_name: str, get_chain: bool = False):
        """
        Retrieve the CA certificate.
        
        Args:
            ca_name: CA name in format "hostname\\CA-Name"
            get_chain: If True, retrieve the full certificate chain
        
        Returns:
            (cert_bytes, None) on success - DER-encoded CA certificate
            (None, Exception) on failure
        """
        try:
            req = GetCACert()
            req['fchain'] = 1 if get_chain else 0
            req['pwszAuthority'] = ca_name + '\x00'
            
            logger.debug(f'Retrieving CA certificate: {ca_name}')
            
            # Direct opnum call on the ACTIVATED ICertRequestD interface — target the
            # interface's own IPID (get_iPid), NOT the IRemUnknown IPID (opnums 0-6);
            # a direct opnum vs get_ipidRemUnknown yields RPC fault 0x800706D1. Same
            # bug/fix as certadmin.py; mirrors impacket's `iface.get_iPid()`.
            resp, err = await self._request(req, IID_ICertRequestD, self.get_iPid())
            if err is not None:
                raise err
            
            cert_data = b''.join(resp['pctbOut']['pb'])
            
            logger.info(f'Retrieved CA certificate: {len(cert_data)} bytes')
            
            return cert_data, None
            
        except Exception as e:
            logger.error(f'Failed to retrieve CA certificate: {e}')
            return None, e
    
    async def _request(self, req, iid, uuid):
        """
        Internal method to make DCOM requests.
        
        Wraps the parent class request() method with proper interface binding.
        """
        return await super().request(req, iid, uuid)

