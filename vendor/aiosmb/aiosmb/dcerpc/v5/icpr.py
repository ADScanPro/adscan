#
# Author: Tamas Jos (@skelsec)
#
# Description:
#   [MS-ICPR] ICertPassage Interface implementation
#
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#

from aiosmb.dcerpc.v5.dtypes import DWORD, LPWSTR, ULONG, LPBYTE, NULL, DWORD_PTR
from aiosmb.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER
from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin
from aiosmb.dcerpc.v5 import system_errors, hresult_errors
from aiosmb.commons.exceptions import SMBException
from aiosmb.dcerpc.v5.structure import Structure


MSRPC_UUID_ICPR  = uuidtup_to_bin(('91ae6020-9e3c-11cf-8d7c-00aa00c091be','0.0'))

class DCERPCSessionError(DCERPCException):
	def __init__(self, error_string=None, error_code=None, packet=None):
		DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__( self ):
		key = self.error_code
		if key in hresult_errors.ERROR_MESSAGES:
			error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
			error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
			return 'ICPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		elif key & 0xffff in system_errors.ERROR_MESSAGES:
			error_msg_short = system_errors.ERROR_MESSAGES[key & 0xffff][0]
			error_msg_verbose = system_errors.ERROR_MESSAGES[key & 0xffff][1]
			return 'ICPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'ICPR SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# CONSTANTS
################################################################################


################################################################################
# STRUCTURES
################################################################################

class CERTTRANSBLOB(NDRSTRUCT):
	structure = (
		('cbData',ULONG),
		('pbData', LPBYTE),
	)

class LPCERTTRANSBLOB(NDRPOINTER):
	referent = (
		('Data', CERTTRANSBLOB),
	)



################################################################################
# RPC CALLS
################################################################################
# 3.2.5.4.1 SchRpcHighestVersion (Opnum 0)
class CertServerRequest(NDRCALL):
	opnum = 0
	structure = (
		('dwFlags', DWORD),
		('pwszAuthority', LPWSTR),
		('pdwRequestId', DWORD_PTR),
		('pctbAttribs', CERTTRANSBLOB),
		('pctbRequest', CERTTRANSBLOB),
		
	)

class CertServerRequestResponse(NDRCALL):
	structure = (
		('pdwRequestId', DWORD_PTR),
		('pdwDisposition', DWORD_PTR),
		('pctbCert', CERTTRANSBLOB),
		('pctbEncodedCert', CERTTRANSBLOB),
		('pctbDispositionMessage', CERTTRANSBLOB),
		('ErrorCode', ULONG),
	)


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (CertServerRequest,CertServerRequestResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
	if string == NULL:
		return string

	if string[-1:] != '\x00':
		return string + '\x00'
	else:
		return string

async def hCertServerRequest(dce, service, csr, dwFlags = 0, pdwRequestId = 1, pctbAttribs = ""):
	request = CertServerRequest()
	request['dwFlags'] = dwFlags
	request['pwszAuthority'] = checkNullString(service)
	request['pdwRequestId'] = pdwRequestId

	# An EMPTY blob MUST marshal as a NULL pointer (cb=0, pb=NULL), NOT as a
	# non-NULL pointer to a zero-length array. On a RETRIEVE (empty CSR, real
	# pdwRequestId) the CA branches on pctbRequest.pb: NULL -> retrieve by
	# request id; non-NULL (even cb=0) -> treat as a NEW submit and ASN.1-parse
	# the empty body -> 0x80093102 CRYPT_E_ASN1_EOD (the ESC7 retrieve failure,
	# HTB Manager 2026-07-24). Mirror certipy/impacket: empty -> NULL.
	attribsblob = CERTTRANSBLOB()
	if pctbAttribs:
		enc_attribs = checkNullString(pctbAttribs).encode('utf-16-le')
		attribsblob['cbData'] = len(enc_attribs)
		attribsblob['pbData'] = enc_attribs
	else:
		attribsblob['cbData'] = 0
		attribsblob['pbData'] = NULL
	request['pctbAttribs'] = attribsblob

	csr_request = CERTTRANSBLOB()
	if csr:
		csr_request['cbData'] = len(csr)
		csr_request['pbData'] = csr
	else:
		csr_request['cbData'] = 0
		csr_request['pbData'] = NULL
	request['pctbRequest'] = csr_request

	return await dce.request(request)
