
import traceback

from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.common.connection.target import DCERPCTarget
from aiosmb.connection import SMBConnection
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5 import icpr
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_CONNECT

### This does not work over SMB, only TCP/IP!


class ICPRRPC:
	def __init__(self):
		self.service_pipename = None #not available via smb
		self.service_uuid = icpr.MSRPC_UUID_ICPR
		self.dce = None

	async def __aenter__(self):
		return self

	async def __aexit__(self, exc_type, exc, traceback):
		await self.close()
		return True,None

	async def close(self):
		try:
			if self.dce:
				try:
					await self.dce.disconnect()
				except:
					pass
				return

			return True,None
		except Exception as e:
			return None, e

	@staticmethod
	async def from_rpcconnection(connection:DCERPC5Connection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		try:
			service = ICPRRPC()
			service.dce = connection

			service.dce.set_auth_level(auth_level)
			if auth_level is None:
				service.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY) #secure default :P

			_, err = await service.dce.connect()
			if err is not None:
				raise err

			_, err = await service.dce.bind(ICPRRPC().service_uuid)
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			return False, e

	@staticmethod
	async def from_smbconnection(connection:SMBConnection, auth_level = None, open:bool = True, perform_dummy:bool = False):
		"""
		Creates the connection to the service using an established SMBConnection.
		This connection will use the given SMBConnection as transport layer.
		"""
		try:
			if auth_level is None:
				#for SMB connection no extra auth needed
				auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

			epm = EPM.from_smbconnection(connection)
			_, err = await epm.connect()
			if err is not None:
				raise err

			constring, err = await epm.map(ICPRRPC().service_uuid)
			if err is not None:
				raise err

			target = DCERPCTarget.from_connection_string(constring, smb_connection = connection)
			dcerpc_auth = DCERPCAuth.from_smb_gssapi(connection.gssapi)
			rpc_connection = DCERPC5Connection(dcerpc_auth, target)

			service, err = await ICPRRPC.from_rpcconnection(rpc_connection, auth_level=auth_level, open=open, perform_dummy = perform_dummy)
			if err is not None:
				raise err

			return service, None
		except Exception as e:
			traceback.print_exc()
			return None, e
		finally:
			if epm is not None:
				await epm.disconnect()

	async def request_certificate(self, ca_name: str, csr: bytes, attributes = None, flags: int = 0):
		"""
		Submit a certificate request to the CA via RPC (MS-ICPR).

		Args:
			ca_name: CA name (e.g., "MyCA" or "DC01\\MyCA")
			csr: DER-encoded certificate signing request
			attributes: Request attributes. Accepted forms (all flattened to the
				MS-WCCE wire format ``"name:value\\nname:value\\n..."``):

				- list of pre-formatted strings — ``['CertificateTemplate:User',
				  'SAN:upn=admin@corp.local']``
				- list of ``(name, value)`` tuples — ``[('CertificateTemplate',
				  'User'), ('SAN', 'upn=admin@corp.local')]``
				- dict — ``{'CertificateTemplate': 'User',
				  'SAN': 'upn=admin@corp.local'}`` (CPython 3.7+ preserves
				  insertion order, so the wire ordering is stable)
			flags: Request flags

		Returns:
			(result_dict, None) on success where result_dict contains:
				- 'request_id': The assigned request ID
				- 'disposition': Disposition code
				- 'certificate': DER-encoded certificate (if issued)
				- 'certificate_chain': Certificate chain data (if issued)
				- 'disposition_message': Error/status message
			(None, Exception) on failure
		"""
		try:
			flattrib = ""
			if attributes:
				if isinstance(attributes, dict):
					pairs = [f"{k}:{v}" for k, v in attributes.items()]
				else:
					pairs = []
					for item in attributes:
						if isinstance(item, str):
							pairs.append(item)
						elif isinstance(item, (tuple, list)) and len(item) == 2:
							pairs.append(f"{item[0]}:{item[1]}")
						else:
							raise TypeError(
								"request_certificate: each attribute must be a "
								"'name:value' string or a (name, value) tuple, "
								f"got {type(item).__name__}"
							)
				flattrib = "\n".join(pairs)

			data, err = await icpr.hCertServerRequest(
				self.dce,
				ca_name,
				csr,
				dwFlags = flags,
				pctbAttribs = flattrib,
				pdwRequestId = 0  # 0 for new requests
			)
			if err is not None:
				raise err

			return self._parse_response(data), None

		except Exception as e:
			return None, e

	async def retrieve_certificate(self, ca_name: str, request_id: int, flags: int = 0):
		"""
		Retrieve a pending certificate by request ID via RPC (MS-ICPR).

		Args:
			ca_name: CA name (e.g., "MyCA" or "DC01\\MyCA")
			request_id: The request ID from a previous submission
			flags: Request flags

		Returns:
			(result_dict, None) on success where result_dict contains:
				- 'request_id': The request ID
				- 'disposition': Disposition code
				- 'certificate': DER-encoded certificate (if issued)
				- 'certificate_chain': Certificate chain data (if issued)
				- 'disposition_message': Error/status message
			(None, Exception) on failure
		"""
		try:
			# Retrieve by request id: dwFlags=0 + empty CSR + pdwRequestId, exactly
			# like certipy/impacket. The retrieve is driven by pdwRequestId; the
			# empty CSR/attribs must marshal as NULL blobs (handled in
			# hCertServerRequest) so the CA does not treat this as a new submit.
			data, err = await icpr.hCertServerRequest(
				self.dce,
				ca_name,
				b'',  # Empty CSR for retrieval
				dwFlags = flags,
				pctbAttribs = "",
				pdwRequestId = request_id
			)
			if err is not None:
				raise err

			return self._parse_response(data), None

		except Exception as e:
			return None, e

	def _parse_response(self, data) -> dict:
		"""Parse certificate server response into a consistent dict format."""
		cert_chain = b''.join(data['pctbCert']['pbData'])
		certificate = b''.join(data['pctbEncodedCert']['pbData'])
		disposition_message = b''.join(data['pctbDispositionMessage']['pbData']).decode('utf-16-le').replace('\x00', '')

		return {
			'request_id': data['pdwRequestId'],
			'disposition': data['pdwDisposition'],
			'certificate': certificate if len(certificate) > 0 else None,
			'certificate_chain': cert_chain if len(cert_chain) > 0 else None,
			'disposition_message': disposition_message if disposition_message else None,
		}

