import asyncio
import traceback

from aiosmb.dcerpc.v5.ndr import NDRCALL
from aiosmb.dcerpc.v5.transport.tcp import DCERPCTCPTransport
from aiosmb.dcerpc.v5.transport.smb import DCERPCSMBTransport
from aiosmb.dcerpc.v5.structure import unpack
from aiosmb.dcerpc.v5.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup
from aiosmb.dcerpc.v5.rpcrt import *
from aiosmb.dcerpc.v5 import hresult_errors
from unicrypto.symmetric import RC4
from badauth.common.winapi.constants import ISC_REQ
import sys


class DCERPC5Connection:
	def __init__(self, gssapi, target):
		self.target = target
		self.gssapi = gssapi

		self.transport = None
		
		if gssapi is None:
			self.auth_type = RPC_C_AUTHN_NONE
		else:
			self.auth_type = RPC_C_AUTHN_WINNT
			if self.gssapi.kerberos is not None:
				self.auth_type = RPC_C_AUTHN_GSS_NEGOTIATE
		
		self.auth_level = RPC_C_AUTHN_LEVEL_NONE
		self.ctx = 0
		self.callid = 1
		# ADSCAN: serializes each request()'s send+recv round-trip on this
		# association. recv() returns the NEXT frame off the wire without
		# correlating call_id, so concurrent request() coroutines sharing one
		# connection would otherwise steal each other's responses (observed:
		# SAMR description / UAC-flag scramble -> wrong-principal attribution).
		self._request_lock = asyncio.Lock()
		self.__auth_ctx_id = None  # Set during initial bind, reused for alter context

		self.NDRSyntax   = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
		self.NDR64Syntax = uuidtup_to_bin(('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
		self.transfer_syntax =  self.NDRSyntax

		self.transfer_syntax = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
		self.__max_xmit_size = 0
		self._max_user_frag = 0

		self.__sequence = 0
		self.__sessionKey = None
		self.__clientSigningKey = None
		self.__serverSigningKey = None
		self.__clientSealingKey = None
		self.__serverSealingKey = None
		self.__clientSealingHandle = None
		self.__serverSealingHandle = None

	def get_session_key(self):
		return self.__sessionKey

	def set_auth_level(self, auth_level):
		self.auth_level = auth_level

	def set_auth_type(self, auth_type):
		self.auth_type = auth_type

	async def disconnect(self):
		try:
			if self.transport is not None:
				await self.transport.disconnect()

			return True, None
		except Exception as e:
			return None, e

	async def connect(self):
		"""
		Selects the correct transport layer based on the self.target and starts it
		"""
		try:
			if self.target.rpcprotocol == 'ncacn_ip_tcp':
				self.transport = DCERPCTCPTransport(self.target)
				await self.transport.connect()

			elif self.target.rpcprotocol == 'ncacn_np':
				self.transport = DCERPCSMBTransport(self.target)
				_, err = await self.transport.connect()
				if err is not None:
					raise err
				self.__sessionKey = self.transport.get_session_key()
			else:
				raise NotImplementedError()

			return True, None
		except Exception as e:
			return None, e

	async def bind(self, iface_uuid, alter = 0, bogus_binds = 0, transfer_syntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')):
		"""
		Performs bind operation. Does authentication and sets up the keys for further communication
		"""
		try:
			bind = MSRPCBind()
			#item['TransferSyntax']['Version'] = 1
			
			# For alter context, increment to get a new context ID
			if alter:
				self.ctx += 1
			
			ctx = self.ctx
			for _ in range(bogus_binds):
				item = CtxItem()
				item['ContextID'] = ctx
				item['TransItems'] = 1
				item['ContextID'] = ctx
				# We generate random UUIDs for bogus binds
				item['AbstractSyntax'] = generate() + stringver_to_bin('2.0')
				item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
				bind.addCtxItem(item)
				self.ctx += 1
				ctx += 1

			# The true one :)
			item = CtxItem()
			item['AbstractSyntax'] = iface_uuid
			item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
			item['ContextID'] = ctx
			item['TransItems'] = 1
			bind.addCtxItem(item)

			packet = MSRPCHeader()
			packet['type'] = MSRPC_BIND
			packet['pduData'] = bind.getData()
			packet['call_id'] = self.callid
			
			if alter:
				packet['type'] = MSRPC_ALTERCTX
				# For alter context with authentication, include sec_trailer to reference existing security context
				if self.auth_level != RPC_C_AUTHN_LEVEL_NONE:
					sec_trailer = SEC_TRAILER()
					sec_trailer['auth_type'] = self.auth_type
					sec_trailer['auth_level'] = self.auth_level
					# Use the SAME auth_ctx_id as the original bind to reference the same security context
					sec_trailer['auth_ctx_id'] = self.__auth_ctx_id
					
					pad = (4 - (len(packet.get_packet()) % 4)) % 4
					if pad != 0:
						packet['pduData'] += b'\xFF' * pad
						sec_trailer['auth_pad_len'] = pad
					
					packet['sec_trailer'] = sec_trailer
					# No auth_data for alter context - we're reusing existing security context

			# For initial bind, we need full authentication
			if self.auth_level != RPC_C_AUTHN_LEVEL_NONE and not alter:
				#authentication required
				if self.auth_type == RPC_C_AUTHN_WINNT:
					
					#seal flag MUST be turned on in the handshake flags!!!!!!!
					#it is "signaled via the is_rpc variable"0
					auth, res, err = await self.gssapi.ntlm.authenticate(
						None, 
						spn=self.target.to_target_string(),
						flags =  ISC_REQ.REPLAY_DETECT |\
									ISC_REQ.CONFIDENTIALITY|\
									ISC_REQ.USE_SESSION_KEY|\
									ISC_REQ.INTEGRITY|\
									ISC_REQ.SEQUENCE_DETECT|\
									ISC_REQ.CONNECTION
					)
					if err is not None:
						return None, err

				elif self.auth_type == RPC_C_AUTHN_NETLOGON:
					return False, Exception('RPC_C_AUTHN_NETLOGON Not implemented!')

				elif self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
					auth, res, err  = await self.gssapi.gssapi.authenticate(
						None, 
						flags = ISC_REQ.CONFIDENTIALITY |\
								ISC_REQ.INTEGRITY | \
								ISC_REQ.SEQUENCE_DETECT | \
								ISC_REQ.REPLAY_DETECT | \
								ISC_REQ.MUTUAL_AUTH | \
								ISC_REQ.USE_DCE_STYLE,
						#seq_number = 0, 
						spn=self.target.to_target_string()
					)
					if err is not None:
						return None, err
				else:
					return None, Exception('Unsupported auth type!')

				sec_trailer = SEC_TRAILER()
				sec_trailer['auth_type']   = self.auth_type
				sec_trailer['auth_level']  = self.auth_level
				# Store the auth_ctx_id for use in alter context
				self.__auth_ctx_id = self.ctx + 79231
				sec_trailer['auth_ctx_id'] = self.__auth_ctx_id

				pad = (4 - (len(packet.get_packet()) % 4)) % 4
				if pad != 0:
					packet['pduData'] += b'\xFF'*pad
					sec_trailer['auth_pad_len']=pad

				packet['sec_trailer'] = sec_trailer
				packet['auth_data'] = auth

			_, err = await self.transport.send(packet.get_packet())
			if err is not None:
				raise err
			
			data, err = await self.recv_one()
			if err is not None:
				raise err
			
			resp = MSRPCHeader(data)

			if resp['type'] == MSRPC_BINDACK or resp['type'] == MSRPC_ALTERCTX_R:
				bindResp = MSRPCBindAck(resp.getData())
			elif resp['type'] == MSRPC_BINDNAK or resp['type'] == MSRPC_FAULT:
				if resp['type'] == MSRPC_FAULT:
					resp = MSRPCRespHeader(resp.getData())
					status_code = unpack('<L', resp['pduData'][:4])[0]
				else:
					resp = MSRPCBindNak(resp['pduData'])
					status_code = resp['RejectedReason']
				if status_code in rpc_status_codes:
					return False, DCERPCException(error_code = status_code)
				elif status_code in rpc_provider_reason:
					return False, DCERPCException("Bind context rejected: %s" % rpc_provider_reason[status_code])
				else:
					return False, DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)
			else:
				return False, DCERPCException('Unknown DCE RPC packet type received: %d' % resp['type'])

			# check ack results for each context, except for the bogus ones
			for ctx in range(bogus_binds+1,bindResp['ctx_num']+1):
				ctxItems = bindResp.getCtxItem(ctx)
				if ctxItems['Result'] != 0:
					msg = "Bind context %d rejected: " % ctx
					msg += rpc_cont_def_result.get(ctxItems['Result'], 'Unknown DCE RPC context result code: %.4x' % ctxItems['Result'])
					msg += "; "
					reason = bindResp.getCtxItem(ctx)['Reason']
					msg += rpc_provider_reason.get(reason, 'Unknown reason code: %.4x' % reason)
					if (ctxItems['Result'], reason) == (2, 1): # provider_rejection, abstract syntax not supported
						msg += " (this usually means the interface isn't listening on the given endpoint)"
					raise DCERPCException(msg)

				# Save the transfer syntax for later use
				self.transfer_syntax = ctxItems['TransferSyntax']

			# The received transmit size becomes the client's receive size, and the received receive size becomes the client's transmit size.
			self.__max_xmit_size = bindResp['max_rfrag']

			# For alter context, skip authentication - the security context is already established
			if self.auth_level != RPC_C_AUTHN_LEVEL_NONE and not alter:
				if self.auth_type == RPC_C_AUTHN_WINNT:
					response, res, err = await self.gssapi.ntlm.authenticate(
						bindResp['auth_data'], 
						spn=self.target.to_target_string(),
						flags =  ISC_REQ.REPLAY_DETECT |\
									ISC_REQ.CONFIDENTIALITY|\
									ISC_REQ.USE_SESSION_KEY|\
									ISC_REQ.INTEGRITY|\
									ISC_REQ.SEQUENCE_DETECT|\
									ISC_REQ.CONNECTION
					)
					if err is not None:
						return None, err
					
					self.__sessionKey = self.gssapi.ntlm.get_session_key()

				elif self.auth_type == RPC_C_AUTHN_NETLOGON:
					response = None
				elif self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
					response, res, err  = await self.gssapi.gssapi.authenticate(
						bindResp['auth_data'],
						flags = 
							ISC_REQ.CONFIDENTIALITY |\
							ISC_REQ.INTEGRITY | \
							ISC_REQ.SEQUENCE_DETECT | \
							ISC_REQ.REPLAY_DETECT | \
							ISC_REQ.MUTUAL_AUTH | \
							ISC_REQ.USE_DCE_STYLE,
						spn=self.target.to_target_string()
					)
					if err is not None:
						return None, err
					
					self.__sessionKey = self.gssapi.gssapi.get_session_key()

				self.__sequence = 0

				if self.auth_level in (RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY):
					if self.auth_type == RPC_C_AUTHN_WINNT:
						if self.gssapi.ntlm.is_extended_security() == True:
							self.__clientSigningKey = self.gssapi.ntlm.get_signkey() 
							self.__serverSigningKey = self.gssapi.ntlm.get_signkey('Server')
							self.__clientSealingKey = self.gssapi.ntlm.get_sealkey() 
							self.__serverSealingKey = self.gssapi.ntlm.get_sealkey('Server')
							cipher3 = RC4(self.__clientSealingKey)
							self.__clientSealingHandle = cipher3.encrypt
							cipher4 = RC4(self.__serverSealingKey)
							self.__serverSealingHandle = cipher4.encrypt
							
						else:
							# Same key for everything
							self.__clientSigningKey = self.gssapi.ntlm.get_session_key()
							self.__serverSigningKey = self.gssapi.ntlm.get_session_key()
							self.__clientSealingKey = self.gssapi.ntlm.get_session_key()
							self.__serverSealingKey = self.gssapi.ntlm.get_session_key()
							cipher = RC4(self.__clientSigningKey)
							self.__clientSealingHandle = cipher.encrypt
							self.__serverSealingHandle = cipher.encrypt
						
					elif self.auth_type == RPC_C_AUTHN_NETLOGON:
						raise Exception('RPC_C_AUTHN_NETLOGON is not implemented!')

				sec_trailer = SEC_TRAILER()
				sec_trailer['auth_type'] = self.auth_type
				sec_trailer['auth_level'] = self.auth_level
				sec_trailer['auth_ctx_id'] = self.__auth_ctx_id

				if response is not None:
					if self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
						alter_ctx = MSRPCHeader()
						alter_ctx['type'] = MSRPC_ALTERCTX
						alter_ctx['pduData'] = bind.getData()
						alter_ctx['sec_trailer'] = sec_trailer
						alter_ctx['auth_data'] = response
						
						_, err = await self.transport.send(alter_ctx.get_packet(), forceWriteAndx = 1)
						if err is not None:
							raise err
						
						self.__sequence = 0
						data, err = await self.recv_one() #recieving the result of alter_context command
						if err is not None:
							raise err

						self.__sequence = self.gssapi.gssapi.get_seq_number()
					else:
						auth3 = MSRPCHeader()
						auth3['type'] = MSRPC_AUTH3
						# pad (4 bytes): Can be set to any arbitrary value when set and MUST be 
						# ignored on receipt. The pad field MUST be immediately followed by a 
						# sec_trailer structure whose layout, location, and alignment are as 
						# specified in section 2.2.2.11
						auth3['pduData'] = b' ' * 4 #SkelSec: I have spent 3 hours to find this bug, that I caused by replacing spaces to tabs :(
						auth3['sec_trailer'] = sec_trailer
						#SkelSec auth3['auth_data'] = response.getData()
						auth3['auth_data'] = response

						# Use the same call_id
						self.callid = resp['call_id']
						auth3['call_id'] = self.callid
						_, err = await self.transport.send(auth3.get_packet(), forceWriteAndx = 1)
						if err is not None:
							raise err

				self.callid += 1
			return resp, None	 # means packet is signed, if verifier is wrong it fails
		
		except Exception as e:
			return False, e

	
	async def request(self, request, uuid=None, checkError=True):
		"""
		Creates a requests then dispateches it to _transport.send for singing/encryption asn sending
		"""
		try:
			if self.transfer_syntax == self.NDR64Syntax:
				request.changeTransferSyntax(self.NDR64Syntax)
				isNDR64 = True
			else:
				isNDR64 = False
			
			# ADSCAN: the send+recv pair MUST be atomic per connection. recv()
			# reads the next frame off the transport without matching call_id to
			# the caller, so without this lock a concurrent request() on the same
			# association can consume this call's response (and vice-versa),
			# scrambling which response is paired with which request.
			async with self._request_lock:
				_, err = await self.call(request.opnum, request, uuid)
				if err is not None:
					raise err

				answer, err = await self.recv()
				if err is not None:
					raise err

			__import__(request.__module__)
			module = sys.modules[request.__module__]
			respClass = getattr(module, request.__class__.__name__ + 'Response')

			if answer[-4:] != b'\x00\x00\x00\x00' and checkError is True:
				error_code = unpack('<L', answer[-4:])[0]
				if error_code in rpc_status_codes:
					
					# This is an error we can handle
					exception = DCERPCException(error_code = error_code)
				else:	
					
					sessionErrorClass = getattr(module, 'DCERPCSessionError')
					try:
						# Try to unpack the answer, even if it is an error, it works most of the times
						response =  respClass(answer, isNDR64 = isNDR64)
					except:
						# No luck :(
						exception = sessionErrorClass(error_code = error_code)
					else:
						exception = sessionErrorClass(packet = response, error_code = error_code)
				return None, exception
			else:
				response =  respClass(answer, isNDR64 = isNDR64)
				return response, None
		except Exception as e:
			return None, e


	async def send(self, data):
		try:
			if isinstance(data, MSRPCHeader) is not True:
				# Must be an Impacket, transform to structure
				data = DCERPC_RawCall(data.OP_NUM, data.get_packet())

			try:
				if data['uuid'] != b'':
					data['flags'] |= PFC_OBJECT_UUID
			except:
				# Structure doesn't have uuid
				pass
			data['ctx_id'] = self.ctx
			data['call_id'] = self.callid
			data['alloc_hint'] = len(data['pduData'])
			# We should fragment PDUs if:
			# 1) Payload exceeds __max_xmit_size received during BIND response
			# 2) We'e explicitly fragmenting packets with lower values
			should_fragment = False

			# Let's decide what will drive fragmentation for this request
			if self._max_user_frag > 0:
				# User set a frag size, let's compare it with the max transmit size agreed when binding the interface
				fragment_size = min(self._max_user_frag, self.__max_xmit_size)
			else:
				fragment_size = self.__max_xmit_size

			# Sanity check. Fragmentation can't be too low, otherwise sec_trailer won't fit

			if self.auth_level in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
				if fragment_size <= 8:
					# Minimum pdu fragment size is 8, important when doing PKT_INTEGRITY/PRIVACY. We need a minimum size of 8
					# (Kerberos)
					fragment_size = 8

			# ToDo: Better calculate the size needed. Now I'm setting a number that surely is enough for Kerberos and NTLM
			# ToDo: trailers, both for INTEGRITY and PRIVACY. This means we're not truly honoring the user's frag request.
			if len(data['pduData']) + 128 > fragment_size:
				should_fragment = True
				if fragment_size+128 > self.__max_xmit_size:
					fragment_size = self.__max_xmit_size - 128

			if should_fragment:
				packet = data['pduData']
				offset = 0

				while 1:
					toSend = packet[offset:offset+fragment_size]
					if not toSend:
						break
					if offset == 0:
						data['flags'] |= PFC_FIRST_FRAG
					else:
						data['flags'] &= (~PFC_FIRST_FRAG)
					offset += len(toSend)
					if offset >= len(packet):
						data['flags'] |= PFC_LAST_FRAG
					else:
						data['flags'] &= (~PFC_LAST_FRAG)
					data['pduData'] = toSend
					_, err = await self._transport_send(data, forceWriteAndx = 1, forceRecv =data['flags'] & PFC_LAST_FRAG)
					if err is not None:
						raise err

			else:
				_, err = await self._transport_send(data)
				if err is not None:
					raise err
			
			self.callid += 1
			return True, None
		except Exception as e:
			return None, e

	
	async def recv(self):
		try:
			finished = False
			retAnswer = b''
			while not finished:
				# At least give me the MSRPCRespHeader, especially important for 
				# TCP/UDP Transports
				response_data, err = await self.transport.recv(1)
				if err is not None:
					raise err

				response_header = MSRPCRespHeader(response_data)

				off = response_header.get_header_size()
				
				if response_header['type'] == MSRPC_FAULT and response_header['frag_len'] >= off+4:
					status_code = unpack("<L",response_data[off:off+4])[0]
					if status_code in rpc_status_codes:
						raise DCERPCException(rpc_status_codes[status_code])
					elif status_code & 0xffff in rpc_status_codes:
						raise DCERPCException(rpc_status_codes[status_code & 0xffff])
					else:
						if status_code in hresult_errors.ERROR_MESSAGES:
							error_msg_short = hresult_errors.ERROR_MESSAGES[status_code][0]
							error_msg_verbose = hresult_errors.ERROR_MESSAGES[status_code][1]
							raise DCERPCException('%s - %s' % (error_msg_short, error_msg_verbose))
						else:
							raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)

				if response_header['flags'] & PFC_LAST_FRAG:
					# No need to reassembly DCERPC
					finished = True
				else:
					# Forcing Read Recv, we need more packets!
					forceRecv = 1
				
				answer = response_data[off:]
				auth_len = response_header['auth_len']
				if auth_len:
					auth_len += 8
					auth_data = answer[-auth_len:]
					sec_trailer = SEC_TRAILER(data = auth_data)
					answer = answer[:-auth_len]
					
					if sec_trailer['auth_level'] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
						if self.auth_type == RPC_C_AUTHN_WINNT:
							if self.gssapi.ntlm.is_extended_security() == True:
								# TODO: FIX THIS, it's not calculating the signature well
								# Since I'm not testing it we don't care... yet
								answer, signature = self.gssapi.ntlm.SEAL(
															self.__serverSigningKey,
															self.__serverSealingKey,
															answer,
															answer,
															self.__sequence,
															self.__serverSealingHandle
														)

							else:
								answer, signature = self.gssapi.ntlm.SEAL(
															self.__serverSigningKey,
															self.__serverSealingKey,
															answer,
															answer,
															self.__sequence,
															self.__serverSealingHandle
														)

								self.__sequence += 1
						elif self.auth_type == RPC_C_AUTHN_NETLOGON:
							raise Exception('RPC_C_AUTHN_NETLOGON is not implemented!')
							#from impacket.dcerpc.v5 import nrpc
							#answer, cfounder = nrpc.UNSEAL(answer, 
							#	   auth_data[len(sec_trailer):],
							#	   self.__sessionKey, 
							#	   False)
							#self.__sequence += 1
						elif self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
							if self.__sequence > 0:
								answer, cfounder = await self.gssapi.gssapi.decrypt(answer, self.__sequence, direction='init', auth_data=auth_data)
					elif sec_trailer['auth_level'] == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
						if self.auth_type == RPC_C_AUTHN_WINNT:
							ntlmssp = auth_data[12:]
							
							if self.gssapi.ntlm.is_extended_security() == True:
								#TODO:
								signature =  self.gssapi.ntlm.SIGN(
									self.__serverSigningKey, 
									answer, 
									self.__sequence, 
									self.__serverSealingHandle
								)
							else:
								signature = self.gssapi.ntlm.SIGN(
									self.__serverSigningKey, 
									ntlmssp, 
									self.__sequence, 
									self.__serverSealingHandle
								)
								
								# Yes.. NTLM2 doesn't increment sequence when receiving
								# the packet :P
								self.__sequence += 1
						elif self.auth_type == RPC_C_AUTHN_NETLOGON:
							raise Exception('RPC_C_AUTHN_NETLOGON is not implemented!')
							#from impacket.dcerpc.v5 import nrpc
							#ntlmssp = auth_data[12:]
							#signature = nrpc.SIGN(ntlmssp, 
							#	   self.__confounder, 
							#	   self.__sequence, 
							#	   self.__sessionKey, 
							#	   False)
							#self.__sequence += 1
						elif self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
							# Do NOT increment the sequence number when Signing Kerberos
							#self.__sequence += 1
							pass

					
					if sec_trailer['auth_pad_len']:
						answer = answer[:-sec_trailer['auth_pad_len']]
				
				retAnswer += answer
			
			return retAnswer, None
		except Exception as e:
			return None, e

	
	async def recv_one(self):
		try:
			finished = False
			forceRecv = 0
			retAnswer = b''
			while not finished:
				# At least give me the MSRPCRespHeader, especially important for 
				# TCP/UDP Transports
				response_data, err = await self.transport.recv(1) #test
				if err is not None:
					raise err
				response_header = MSRPCRespHeader(response_data)

				off = response_header.get_header_size()

				if response_header['type'] == MSRPC_FAULT and response_header['frag_len'] >= off+4:
					status_code = unpack("<L",response_data[off:off+4])[0]
					if status_code in rpc_status_codes:
						return None, DCERPCException(rpc_status_codes[status_code])
					elif status_code & 0xffff in rpc_status_codes:
						return None,  DCERPCException(rpc_status_codes[status_code & 0xffff])
					else:
						if status_code in hresult_errors.ERROR_MESSAGES:
							error_msg_short = hresult_errors.ERROR_MESSAGES[status_code][0]
							error_msg_verbose = hresult_errors.ERROR_MESSAGES[status_code][1] 
							return None,  DCERPCException('%s - %s' % (error_msg_short, error_msg_verbose))
						else:
							return None,  DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)

				if response_header['flags'] & PFC_LAST_FRAG:
					# No need to reassembly DCERPC
					finished = True
				else:
					# Forcing Read Recv, we need more packets!
					forceRecv = 1
					
			return response_data, None
		except Exception as e:
			return None, e
	
	async def _transport_send(self, rpc_packet, forceWriteAndx = 0, forceRecv = 0):
		"""
		This function does the signing and ecryption on the data we want to send out.
		Keys are set up during bind
		"""
		try:
			rpc_packet['ctx_id'] = self.ctx
			rpc_packet['sec_trailer'] = b''
			rpc_packet['auth_data'] = b''

			if self.auth_level in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
				# Dummy verifier, just for the calculations
				sec_trailer = SEC_TRAILER()
				sec_trailer['auth_type'] = self.auth_type
				sec_trailer['auth_level'] = self.auth_level
				sec_trailer['auth_pad_len'] = 0
				sec_trailer['auth_ctx_id'] = self.__auth_ctx_id if self.__auth_ctx_id is not None else self.ctx + 79231

				pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
				if pad != 0:
					rpc_packet['pduData'] += b'\xBB'*pad
					sec_trailer['auth_pad_len']=pad

				rpc_packet['sec_trailer'] = sec_trailer.getData()
				rpc_packet['auth_data'] = b' '*16

				plain_data = rpc_packet['pduData']
				if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
					if self.auth_type == RPC_C_AUTHN_WINNT:
						if self.gssapi.ntlm.is_extended_security() == True:
							sealedMessage, signature = self.gssapi.ntlm.SEAL(
								self.__clientSigningKey, 
								self.__clientSealingKey,
								rpc_packet.get_packet()[:-16],
								plain_data,
								self.__sequence,
								self.__clientSealingHandle
							)
						else:
							sealedMessage, signature = self.gssapi.ntlm.SEAL(
								self.__clientSigningKey, 
								self.__clientSealingKey,
								plain_data,
								plain_data,
								self.__sequence,
								self.__clientSealingHandle
							)
						
					elif self.auth_type == RPC_C_AUTHN_NETLOGON:
						raise Exception('RPC_C_AUTHN_NETLOGON is not implemented!')
						#from impacket.dcerpc.v5 import nrpc
						#sealedMessage, signature = nrpc.SEAL(plain_data, self.__confounder, self.__sequence, self.__sessionKey, False)
					elif self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
						sealedMessage, signature = await self.gssapi.gssapi.encrypt(plain_data, self.__sequence)
					rpc_packet['pduData'] = sealedMessage

				elif self.auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: 
					if self.auth_type == RPC_C_AUTHN_WINNT:
						if self.gssapi.ntlm.is_extended_security() == True:
							# Interesting thing.. with NTLM2, what is is signed is the 
							# whole PDU, not just the data
							signature =  self.gssapi.ntlm.SIGN(self.__clientSigningKey, 
								rpc_packet.get_packet()[:-16], 
								self.__sequence, 
								self.__clientSealingHandle)
						else:
							signature =  self.gssapi.ntlm.SIGN(self.__clientSigningKey, 
								plain_data, 
								self.__sequence, 
								self.__clientSealingHandle)
					elif self.auth_type == RPC_C_AUTHN_NETLOGON:
						raise Exception('RPC_C_AUTHN_NETLOGON is not implemented!')
						#from impacket.dcerpc.v5 import nrpc
						#signature = nrpc.SIGN(plain_data, 
						#	   self.__confounder, 
						#	   self.__sequence, 
						#	   self.__sessionKey, 
						#	   False)
					elif self.auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
						signature = await self.gssapi.gssapi.sign(plain_data, self.__sequence)

				rpc_packet['sec_trailer'] = sec_trailer.getData()
				rpc_packet['auth_data'] = signature

				self.__sequence += 1

			_, err = await self.transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)
			if err is not None:
				raise err
			return True, None
		except Exception as e:
			return None, e

	async def call(self, function, body, uuid=None):
		try:
			if hasattr(body, 'getData'):
				t, err = await self.send(DCERPC_RawCall(function, body.getData(), uuid))
				if err is not None:
					raise err
				return t, None
			else:
				t, err = await self.send(DCERPC_RawCall(function, body, uuid))
				if err is not None:
					raise err
				return t, None
		except Exception as e:
			return None, e

		
	#def alter_ctx(self, newUID, bogus_binds = 0):
	#	answer = self.__class__(self.transport)
	#
	#	answer.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
	#						   self.__aesKey, self.__TGT, self.__TGS)
	#	answer.set_auth_type(self.__auth_type)
	#	answer.set_auth_level(self.__auth_level)
	#
	#	answer.set_ctx_id(self.ctx+1)
	#	answer.__callid = self.callid
	#	answer.bind(newUID, alter = 1, bogus_binds = bogus_binds, transfer_syntax = bin_to_uuidtup(self.transfer_syntax))
	#	return answer