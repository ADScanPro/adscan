import asyncio
from typing import List, Dict
import ssl

from badldap import logger
from badldap.commons.common import MSLDAPClientStatus
from .commons.target import MSLDAPTarget
from badldap.protocol.messages import LDAPMessage, BindRequest, \
	protocolOp, AuthenticationChoice, SaslCredentials, \
	SearchRequest, AttributeDescription, Filter, Filters, \
	Controls, Control, SearchControlValue, AddRequest, \
	ModifyRequest, DelRequest, ModifyDNRequest, ExtendedRequest, ExtendedResponse

from badldap.protocol.utils import calcualte_length
from badldap.protocol.typeconversion import convert_result, convert_attributes, encode_attributes, encode_changes
from badldap.protocol.query import escape_filter_chars, query_syntax_converter
from badldap.commons.authbuilder import get_auth_context
from badldap.network.packetizer import LDAPPacketizer
from asysocks.unicomm.common.target import UniProto
from badldap.commons.exceptions import LDAPBindException, LDAPAddException, LDAPModifyException, LDAPDeleteException, LDAPModifyDNException, LDAPSearchException
from hashlib import sha256
from asysocks.unicomm.client import UniClient
from badauth.common.constants import asyauthProtocol
from badauth.common.credentials import UniCredential
from badauth.common.winapi.constants import ISC_REQ


def _complete_ldap_message_length(buf):
	"""Return the byte length of the leading LDAP message in ``buf`` iff a
	COMPLETE message is present; otherwise ``None`` (need more bytes).

	Unlike :func:`calcualte_length`, this NEVER decodes a truncated BER header
	(which would yield a too-small length, or IndexError) — it returns ``None``
	until both the full length header AND the full payload are buffered. This is
	what lets the incoming path hold a message that is split across multiple
	SASL/GSS-wrapped buffers until it is complete, instead of mis-parsing a
	partial entry.
	"""
	if len(buf) < 2:
		return None
	if buf[1] <= 127:
		header_len = 2
	else:
		bcount = buf[1] - 128
		header_len = 2 + bcount
		if len(buf) < header_len:
			return None
	msg_len = calcualte_length(buf)
	if msg_len is None or len(buf) < msg_len:
		return None
	return msg_len


class MSLDAPClientConnection:
	def __init__(self, target:MSLDAPTarget, credential:UniCredential, auth=None):
		self.target = target
		self.credential = credential
		if auth is not None:
			self.auth = auth
		else:
			self.auth = get_auth_context(self.credential)

		self.connected = False
		self.bind_ok = False
		self.is_anon = False
		self.__sign_messages = False
		self.__encrypt_messages = False
		# Plaintext reassembly buffer for the incoming path. A single LDAP
		# message can be larger than the server's GSS max-wrap size and arrive
		# split across multiple sealed/signed SASL buffers; decrypted plaintext
		# is accumulated here and only COMPLETE LDAP messages are emitted, with
		# any partial remainder carried to the next buffer. See __handle_incoming.
		self.__recv_buffer = b''
		self.network = None
		self.connection_closed_evt = None

		self.handle_incoming_task = None
		self.status = MSLDAPClientStatus.RUNNING
		self.lasterror = None

		self.message_id = 0
		self.message_table = {}
		self.message_table_notify = {}
		# ADSCAN diagnostic counters (sizes/counts only — never any wire bytes).
		# Used by the bracket-free 'ldap-conn-closed' debug log at the recv-loop
		# close point to distinguish a clean close after N messages from a close
		# mid-response (a non-empty reassembly buffer = a partial/cut message).
		self._recv_buffers_total = 0      # number of (decrypted) buffers drained
		self._recv_plaintext_bytes = 0    # cumulative decrypted plaintext bytes
		self._messages_dispatched = 0     # complete LDAP messages emitted
		self._last_message_id_seen = None # most recent messageID dispatched
		self._largest_message_bytes = 0   # largest single LDAP message seen
		self.encryption_sequence_counter = 0 # this will be set by the inderlying auth algo
		self.cb_data = None #for channel binding
		self._disable_channel_binding = False # putting it here for scanners to be able to turn it off
		self._disable_signing = False
		self._null_channel_binding = False
		# ADSCAN PATCH (2026-05-29) — when True, ``connect()`` upgrades the plain
		# TCP/389 session to TLS via StartTLS (RFC 2830) immediately after the
		# socket is established and BEFORE any bind, so anonymous, SIMPLE, and
		# authenticated binds all run over a confidential channel without
		# needing port 636 or channel binding. Wired by ADscan's confidentiality
		# ladder (services/ldap_transport_service.py). Defaults to False so it
		# never affects callers that did not opt in.
		self._use_starttls = False

		if self.credential.protocol == asyauthProtocol.NONE:
			self.is_anon = True
	
	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		await asyncio.wait_for(self.disconnect(), timeout = 1)

	async def __handle_incoming(self):
		try:
			
			async for message_data in self.network.read():
				if message_data is None:
					break	
				#print('Incoming message data: %s' % message_data)
				if self.bind_ok is True:
					if self.__encrypt_messages is True:
						#removing size
						message_data = message_data[4:]
						try:
							# seq number doesnt matter here, a it's in the header
							message_data, err = await self.auth.decrypt(message_data, 0 )
							if err is not None:
								raise err
						except Exception:
							# ADSCAN log-hygiene: never dump the failing wire/auth state
							# to stdout (it bypasses telemetry and can carry decrypted/
							# sealed message bytes). Route a type-only note through the
							# bridged logger and re-raise to preserve control flow.
							logger.debug('LDAP message decrypt failed')
							raise
						
					elif self.__sign_messages is True:
						message_data = message_data[4:]
						try:
							message_data = await self.auth.unsign(message_data)
						except Exception:
							# ADSCAN log-hygiene: see decrypt path above.
							logger.debug('LDAP message unsign failed')
							raise
				
				
				# Reassemble across buffers. A single LDAP message can exceed the
				# server's GSS max-wrap size and arrive split over multiple sealed/
				# signed SASL buffers; equally, one buffer can carry several small
				# messages. Append the (decrypted) plaintext to the persistent
				# buffer and drain every COMPLETE LDAP message, holding any partial
				# remainder for the next buffer. Framing each buffer in isolation
				# broke on large entries (e.g. a binary nTSecurityDescriptor) with
				# "Insufficient data - N bytes requested but only M available" and
				# tore down the whole connection.
				self.__recv_buffer += message_data
				# ADSCAN diagnostic accounting (sizes/counts only).
				self._recv_buffers_total += 1
				self._recv_plaintext_bytes += len(message_data)
				messages = []
				while True:
					msg_len = _complete_ldap_message_length(self.__recv_buffer)
					if msg_len is None:
						break
					if msg_len > self._largest_message_bytes:
						self._largest_message_bytes = msg_len
					messages.append(LDAPMessage.load(self.__recv_buffer[:msg_len]))
					self.__recv_buffer = self.__recv_buffer[msg_len:]

				if len(messages) == 0:
					# No complete message yet — wait for the next buffer.
					continue

				message_id = messages[0]['messageID'].native
				# ADSCAN diagnostic accounting.
				self._messages_dispatched += len(messages)
				self._last_message_id_seen = message_id
				if message_id not in self.message_table:
					self.message_table[message_id] = []
				self.message_table[message_id].extend(messages)
				if message_id not in self.message_table_notify:
					self.message_table_notify[message_id] = asyncio.Event()
				self.message_table_notify[message_id].set()

			# ADSCAN diagnostic (bracket-free marker; sizes/counts/ids only, no
			# wire bytes / no credential material). The recv loop ended because
			# network.read() returned None = the peer closed the TCP connection.
			# A NON-EMPTY reassembly buffer here means the socket closed
			# MID-RESPONSE (a partial/cut LDAP message) — the strong signal of a
			# sealed-channel cut on a large response (e.g. a big nTSecurityDescriptor
			# over SASL sign/seal). An empty buffer means a clean close after the
			# last complete message (whose id is last_message_id). 'seal' reflects
			# whether the channel was GSS sealed (encrypt) or signed.
			seal_state = 'seal' if self.__encrypt_messages else ('sign' if self.__sign_messages else 'none')
			logger.debug(
				'ldap-conn-closed: peer closed the connection. '
				'seal=%s buffers=%d plaintext_bytes=%d messages=%d '
				'last_message_id=%s largest_message_bytes=%d '
				'recv_buffer_pending=%d mid_response=%s lasterror=%s'
				% (
					seal_state,
					self._recv_buffers_total,
					self._recv_plaintext_bytes,
					self._messages_dispatched,
					self._last_message_id_seen,
					self._largest_message_bytes,
					len(self.__recv_buffer),
					len(self.__recv_buffer) > 0,
					type(self.lasterror).__name__ if self.lasterror is not None else 'none',
				)
			)
			raise Exception('Connection closed!')
		except asyncio.CancelledError:
			self.status = MSLDAPClientStatus.STOPPED
			return

		except Exception as e:
			self.status = MSLDAPClientStatus.ERROR
			self.lasterror = e
			for msgid in self.message_table_notify:
				self.message_table[msgid] = [e]
				self.message_table_notify[msgid].set()
		
		finally:
			if self.connection_closed_evt is not None:
				self.connection_closed_evt.set()
			self.status = MSLDAPClientStatus.STOPPED



	async def send_message(self, message:Dict[str, object]):

		###### EMERGENCY DEBUG ######
		#print('DEBUG: Sending message: %s' % message)
		###### EMERGENCY DEBUG ######

		curr_msg_id = self.message_id
		self.message_id += 1

		message['messageID'] = curr_msg_id
		message_data = LDAPMessage(message).dump()

		if self.bind_ok is True:
			if self.__encrypt_messages is True:
				message_data, signature = await self.auth.encrypt(message_data, self.encryption_sequence_counter)
				message_data = signature + message_data
				message_data = len(message_data).to_bytes(4, byteorder = 'big', signed = False) + message_data
				self.encryption_sequence_counter += 1
			elif self.__sign_messages is True:
				signature = await self.auth.sign(message_data, self.encryption_sequence_counter)
				message_data = signature + message_data
				message_data = len(message_data).to_bytes(4, byteorder = 'big', signed = False) + message_data
				self.encryption_sequence_counter += 1
		
		self.message_table_notify[curr_msg_id] = asyncio.Event()
		await self.network.write(message_data)

		return curr_msg_id

	async def recv_message(self, message_id:int):
		if message_id not in self.message_table_notify:
			logger.debug('Requested message id %s which is not in the message notify table!' % message_id)
			return None
		#print('Waiting for %s' % message_id)
		await self.message_table_notify[message_id].wait()
		#print(self.message_table)
		messages = self.message_table[message_id]

		#print('%s arrived!' % message_id)

		self.message_table[message_id] = []
		self.message_table_notify[message_id].clear()

		return messages

	def get_extra_info(self):
		try:
			ntlm_data = self.auth.get_extra_info()
			if ntlm_data is not None:
				ntlm_data = ntlm_data.to_dict()
		except Exception:
			# ADSCAN log-hygiene: the original ``traceback.print_exc()`` here
			# (a) leaked the NTLM auth context to stdout, bypassing telemetry,
			# and (b) raised NameError because ``traceback`` is not imported at
			# module scope. Route a type-only note through the bridged logger.
			logger.debug('get_extra_info failed to extract NTLM data')
			ntlm_data = None
		return {'ntlm_data' : ntlm_data}

	async def connect(self):
		"""
		Connects to the remote server. Establishes the session, but doesn't perform binding.
		This function MUST be called first before the `bind` operation.

		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			logger.debug('Connecting!')
			self.connection_closed_evt = asyncio.Event()
			packetizer = LDAPPacketizer()
			client = UniClient(self.target, packetizer)
			self.network = await asyncio.wait_for(client.connect(), timeout=self.target.timeout)
			
			# now processing channel binding options
			if self.target.protocol == UniProto.CLIENT_SSL_TCP and self._disable_channel_binding is False:
				if self._null_channel_binding is True:
					self.cb_data = b'tls-server-end-point:' + sha256(b'').digest()
				else:
					certdata = self.network.get_peer_certificate()
					self.cb_data = b'tls-server-end-point:' + sha256(certdata).digest()

			self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
			self.status = MSLDAPClientStatus.CONNECTED
			# ADSCAN PATCH (2026-05-29) — opt-in StartTLS upgrade BEFORE bind.
			# When the confidentiality ladder requests StartTLS on a plain
			# TCP/389 connection, wrap the transport in TLS now (RFC 2830) so
			# the subsequent bind (anonymous, SIMPLE, or authenticated) and all
			# queries travel encrypted. ``starttls()`` leaves the connection in
			# CONNECTED state, exactly what ``bind()`` expects next. A refused
			# StartTLS (no DC cert / not supported) surfaces as an error so the
			# ladder can fall through to the SASL sign+seal rung.
			if getattr(self, '_use_starttls', False) and self.target.protocol == UniProto.CLIENT_TCP:
				tls_ok, tls_err = await self.starttls()
				if tls_err is not None:
					return False, tls_err
			logger.debug('Connection succsessful!')
			return True, None
		except Exception as e:
			return False, e

	async def disconnect(self):
		"""
		Tears down the connection.

		:return: Nothing
		:rtype: None
		"""

		logger.debug('Disconnecting!')
		self.bind_ok = False
		if self.connection_closed_evt is not None:
			self.connection_closed_evt.set()
		
		if self.network is not None:
			await self.network.close()
			await asyncio.sleep(0)
		
		if self.handle_incoming_task is not None:
			self.handle_incoming_task.cancel()


	def __bind_success(self):
		"""
		Internal function invoked after bind finished. 
		Instructs the network layer that upcoming messages might be wrapped
		"""
		logger.debug('BIND Success!')
		self.bind_ok = True
		self.status = MSLDAPClientStatus.RUNNING
		if self.credential.protocol in [asyauthProtocol.NTLM, asyauthProtocol.KERBEROS, asyauthProtocol.SICILY]:
			self.__sign_messages = self.auth.signing_needed()
			self.__encrypt_messages = self.auth.encryption_needed()
			if self.__encrypt_messages or self.__sign_messages:
				self.network.packetizer.is_plain_msg = False

	async def bind(self):
		"""
		Performs the bind operation.
		This is where the authentication happens. Remember to call `connect` before this function!

		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		if self.status != MSLDAPClientStatus.CONNECTED:
			raise Exception("Connect to the LDAP server before binding.")
		logger.debug('BIND in progress...')
		try:
			if self.credential.protocol == asyauthProtocol.SICILY:
				flags = ISC_REQ.CONNECTION|ISC_REQ.CONFIDENTIALITY|ISC_REQ.INTEGRITY
				if self.target.protocol == UniProto.CLIENT_SSL_TCP:
					flags = ISC_REQ.CONNECTION
				
				# this switch is for the case when we are using NTLM and we want to disable signing
				# useful for testing if the server supports it
				if self._disable_signing is True:
					flags = ISC_REQ.CONNECTION
				
				logger.debug('SICILY bind with flags: %s' % flags)

				logger.debug('SICILY iter0: calling auth.authenticate(None) to obtain NEGOTIATE (relay handler must produce it)')
				data, to_continue, err = await self.auth.authenticate(None, spn=self.target.to_target_string(), flags=flags, cb_data = self.cb_data)
				if err is not None:
					logger.debug('SICILY iter0: auth.authenticate(None) returned error: %s' % err)
					return None, err
				logger.debug('SICILY iter0: NEGOTIATE obtained (%d bytes), to_continue=%s' % (len(data) if data else 0, to_continue))

				auth = {
					'sicily_disco' : b''
				}

				bindreq = {
					'version' : 3,
					'name' : 'NTLM'.encode(),
					'authentication': AuthenticationChoice(auth), 
				}

				br = { 'bindRequest' : BindRequest( bindreq	)}
				msg = { 'protocolOp' : protocolOp(br)}
				
				msg_id = await self.send_message(msg)
				res = await self.recv_message(msg_id)
				res = res[0]
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] != 'success':
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)
				
				auth = {
					'sicily_nego' : data
				}

				bindreq = {
					'version' : 3,
					'name' : 'NTLM'.encode(),
					'authentication': AuthenticationChoice(auth), 
				}

				br = { 'bindRequest' : BindRequest( bindreq	)}
				msg = { 'protocolOp' : protocolOp(br)}
				
				msg_id = await self.send_message(msg)
				res = await self.recv_message(msg_id)
				res = res[0]
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] != 'success':
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)

				logger.debug('SICILY DC returned CHALLENGE (%d bytes); calling auth.authenticate(challenge) to obtain AUTHENTICATE' % (len(res['protocolOp']['matchedDN']) if res['protocolOp']['matchedDN'] else 0))
				data, to_continue, err = await self.auth.authenticate(res['protocolOp']['matchedDN'], spn=self.target.to_target_string(), cb_data = self.cb_data)
				if err is not None:
					logger.debug('SICILY iter1: auth.authenticate(challenge) returned error: %s' % err)
					return None, err
				logger.debug('SICILY iter1: AUTHENTICATE obtained (%d bytes), bind handshake complete' % (len(data) if data else 0))

				auth = {
					'sicily_resp' : data
				}

				bindreq = {
					'version' : 3,
					'name' : 'NTLM'.encode(),
					'authentication': AuthenticationChoice(auth), 
				}

				br = { 'bindRequest' : BindRequest( bindreq	)}
				msg = { 'protocolOp' : protocolOp(br)}
				
				msg_id = await self.send_message(msg)
				res = await self.recv_message(msg_id)
				res = res[0]
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] != 'success':
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)
				

				self.__bind_success()
				return True, None

			elif self.credential.protocol == asyauthProtocol.SIMPLE:
				pw = b''
				if self.auth.secret != None:
					pw = self.auth.secret.encode()

				user = b''
				if self.auth.username != None:
					user = self.auth.username.encode()
					if self.auth.domain != None:
						user = self.auth.domain.encode() + b"\\" + user
				if user == b'':
					self.is_anon = True
				
				auth = {
					'simple' : pw
				}

				bindreq = {
					'version' : 3,
					'name': user,
					'authentication': AuthenticationChoice(auth), 
				}

				br = { 'bindRequest' : BindRequest( bindreq	)}
				msg = { 'protocolOp' : protocolOp(br)}
					
				msg_id = await self.send_message(msg)
				res = await self.recv_message(msg_id)
				res = res[0]
				if isinstance(res, Exception):
					return False, res
				res = res.native
				if res['protocolOp']['resultCode'] == 'success':
					self.__bind_success()
					return True, None
				
				else:
					return False, LDAPBindException(
							res['protocolOp']['resultCode'], 
							res['protocolOp']['diagnosticMessage']
						)

			elif self.credential.protocol in [asyauthProtocol.NTLM, asyauthProtocol.KERBEROS]:
				challenge = None
				while True:
					try:
						# MUTUAL_AUTH is REQUIRED for a GSS sign+seal LDAP bind on plain 389.
						# Without it the Kerberos AP-REQ carries ap-options=0x00 (no mutual-
						# required), so the acceptor never returns an AP-REP and no GSS acceptor
						# subkey is negotiated; the per-message seal is then keyed off the bare
						# TGS session key. Windows AD tolerates this, but a Samba 4 AD DC
						# (Heimdal GSS) cannot unwrap the first sealed PDU and silently CLOSES
						# the connection right after the bind succeeds (badldap surfaced this as
						# 'Connection closed!' at the first post-bind sealed query). Real LDAP
						# clients (cyrus-sasl, Windows) always set mutual-required for a sealed
						# bind; mirror that. TLS (LDAPS/StartTLS) and the disable-signing probe
						# override flags below, so MUTUAL_AUTH is scoped to the plain sign+seal
						# rung that needs it.
						flags = ISC_REQ.CONNECTION|ISC_REQ.CONFIDENTIALITY|ISC_REQ.INTEGRITY|ISC_REQ.MUTUAL_AUTH
						if self.target.protocol == UniProto.CLIENT_SSL_TCP:
							flags = ISC_REQ.CONNECTION
						
						# this switch is for the case when we want to disable signing
						# useful for testing if the server supports it
						if self._disable_signing is True:
							flags = ISC_REQ.CONNECTION
						
						data, to_continue, err = await self.auth.authenticate(challenge, cb_data = self.cb_data, spn=self.target.to_target_string(), flags=flags)
						if err is not None:
							raise err
					except Exception as e:
						return False, e
					
					sasl = {
						'mechanism' : 'GSS-SPNEGO'.encode(),
						'credentials' : data,
					}
					auth = {
						'sasl' : SaslCredentials(sasl)
					}

					bindreq = {
						'version' : 3,
						'name': b'',
						'authentication': AuthenticationChoice(auth), 
					}

					br = { 'bindRequest' : BindRequest( bindreq	)}
					msg = { 'protocolOp' : protocolOp(br)}
					
					msg_id = await self.send_message(msg)
					res = await self.recv_message(msg_id)
					res = res[0]
					if isinstance(res, Exception):
						return False, res
					res = res.native
					if res['protocolOp']['resultCode'] == 'success':
						if 'serverSaslCreds' in res['protocolOp']:
							data, _, err = await self.auth.authenticate(res['protocolOp']['serverSaslCreds'], cb_data = self.cb_data, spn=self.target.to_target_string(), flags=flags)
							if err is not None:
								return False, err

						if self.auth.encryption_needed() is True or self.auth.signing_needed() is True:
							self.encryption_sequence_counter = self.auth.get_seq_number()
						self.__bind_success()

						return True, None

					elif res['protocolOp']['resultCode'] == 'saslBindInProgress':
						challenge = res['protocolOp']['serverSaslCreds']
						continue

					else:
						return False, LDAPBindException(
								res['protocolOp']['resultCode'], 
								res['protocolOp']['diagnosticMessage']
							)
			elif self.credential.protocol == asyauthProtocol.SSL:
				if self.target.protocol == UniProto.CLIENT_SSL_TCP:
					# NOTE! If LDAPS is used with SSL authentication, EXTERNAL bid is NOT needed!
					# Again, it is NOT needed!
					# If the handshake is successful, the client is authenticated (but sometimes not?)
					self.__bind_success()
					return True, None
				elif self.target.protocol == UniProto.CLIENT_TCP:
					_, err = await self.starttls()
					if err is not None:
						return False, err
					
					sasl = {
						'mechanism' : 'EXTERNAL'.encode(),
					}
					auth = {
						'sasl' : SaslCredentials(sasl)
					}

					bindreq = {
						'version' : 3,
						'name': b'',
						'authentication': AuthenticationChoice(auth), 
					}

					br = { 'bindRequest' : BindRequest( bindreq	)}
					msg = { 'protocolOp' : protocolOp(br)}

					msg_id = await self.send_message(msg)
					res = await self.recv_message(msg_id)
					if isinstance(res[0], Exception):
						return False, res[0]
					resp = res[0].native['protocolOp']
					if resp['resultCode'] != 'success':
						#startls refused :(
						return False, LDAPBindException(
								resp['resultCode'], 
								resp['diagnosticMessage']
							)
					self.__bind_success()
					return True, None
				
				return False, Exception('Not implemented: %s' % self.credential.protocol.name)
					
			else:
				raise Exception('Not implemented authentication method: %s' % self.credential.protocol.name)
			
		except Exception as e:
			await self.disconnect()
			return False, e

	async def starttls(self):
		try:
			# https://www.ietf.org/rfc/rfc2830.txt
			ext = {
				'requestName': b'1.3.6.1.4.1.1466.20037', 
			}
			br = { 'extendedReq' : ExtendedRequest(ext)}
			msg = { 'protocolOp' : protocolOp(br)}
			msg_id = await self.send_message(msg)
			res = await self.recv_message(msg_id)
			if isinstance(res[0], Exception):
				return False, res[0]
			resp = res[0].native['protocolOp']
			if resp['resultCode'] != 'success':
				#startls refused :(
				return False, LDAPBindException(
						resp['resultCode'], 
						resp['diagnosticMessage']
					)
			self.handle_incoming_task.cancel()
			await asyncio.sleep(0)
			await self.network.wrap_ssl(self.target.get_ssl_context(ssl.PROTOCOL_TLS_CLIENT))
			self.handle_incoming_task = asyncio.create_task(self.__handle_incoming())
			self.status = MSLDAPClientStatus.CONNECTED
			await asyncio.sleep(0)
			return True, None
		except Exception as e:
			# ADSCAN PATCH (2026-05-29) — silence the raw ``print(e)`` that leaked
			# StartTLS failures to stdout and corrupted Rich Live rendering. The
			# error is returned to the caller; logging it is sufficient.
			logger.debug('StartTLS failed: %s' % e)
			return False, e

	async def add(self, entry:str, attributes:Dict[str, object], controls:List[Control] = None):
		"""
		Performs the add operation.
		
		:param entry: The DN of the object to be added
		:type entry: str
		:param attributes: Attributes to be used in the operation
		:type attributes: dict
		:param controls: additional controls to be passed in the query
		:type controls: List[class:`Control`] 
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			req = {
				'entry' : entry.encode(),
				'attributes' : encode_attributes(attributes)
			}
			logger.debug(req)
			br = { 'addRequest' : AddRequest(req)}
			msg = { 'protocolOp' : protocolOp(br)}
			if controls is not None:
				msg['controls'] = controls
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'addResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPAddException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e

	async def modify(self, entry:str, changes:Dict[str, object], controls:List[Control] = None, encode=True,):
		"""
		Performs the modify operation.
		
		:param entry: The DN of the object whose attributes are to be modified
		:type entry: str
		:param changes: Describes the changes to be made on the object. Must be a dictionary of the following format: {'attribute': [('change_type', [value])]}
		:type changes: dict
		:param controls: additional controls to be passed in the query
		:type controls: List[class:`Control`] 
		:param encode: encode the changes provided before sending them to the server
    	:type encode: bool

		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			req = {
				'object' : entry.encode(),
				'changes' : encode_changes(changes, encode)
			}
			br = { 'modifyRequest' : ModifyRequest(req)}
			msg = { 'protocolOp' : protocolOp(br)}
			if controls is not None:
				msg['controls'] = controls
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'modifyResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPModifyException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e

	async def delete(self, entry:str):
		"""
		Performs the delete operation.
		
		:param entry: The DN of the object to be deleted
		:type entry: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			br = { 'delRequest' : DelRequest(entry.encode())}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'delResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPDeleteException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e

	async def modify_dn(self, entry:str, newrdn:str, deleteoldrdn:bool = True, newSuperior:str = None):
		"""
		Performs the modify DN operation.
		
		:param entry: The DN of the object to be renamed/moved
		:type entry: str
		:param newrdn: The new RDN (relative distinguished name) for the entry
		:type newrdn: str
		:param deleteoldrdn: Whether to delete the old RDN value from the entry. Default: True
		:type deleteoldrdn: bool
		:param newSuperior: Optional new parent DN if moving the entry to a new location
		:type newSuperior: str
		:return: A tuple of (True, None) on success or (False, Exception) on error. 
		:rtype: (:class:`bool`, :class:`Exception`)
		"""
		try:
			req = {
				'entry': entry.encode(),
				'newrdn': newrdn.encode(),
				'deleteoldrdn': deleteoldrdn,
			}
			if newSuperior is not None:
				req['newSuperior'] = newSuperior.encode()
			
			br = { 'modDNRequest' : ModifyDNRequest(req)}
			msg = { 'protocolOp' : protocolOp(br)}
			
			msg_id = await self.send_message(msg)
			results = await self.recv_message(msg_id)
			if isinstance(results[0], Exception):
				return False, results[0]
			
			for message in results:
				msg_type = message['protocolOp'].name
				message = message.native
				if msg_type == 'modDNResponse':
					if message['protocolOp']['resultCode'] != 'success':
						return False, LDAPModifyDNException(
							entry,
							message['protocolOp']['resultCode'],
							message['protocolOp']['diagnosticMessage']
						)

			return True, None
		except Exception as e:
			return False, e
	
	async def search(self, base:str, query:str, attributes:List[bytes], search_scope:int = 2, size_limit:int = 1000, types_only:bool = False, derefAliases:int = 0, timeLimit:int = None, controls:List[Control] = None, return_done:bool = False):
		"""
		Performs the search operation.
		
		:param base: base tree on which the search should be performed
		:type base: str
		:param query: filter query that defines what should be searched for
		:type query: str
		:param attributes: a list of attributes to be included in the response
		:type attributes: List[bytes]
		:param search_scope: Specifies the search operation's scope. Default: 2 (Subtree)
		:type search_scope: int
		:param types_only: indicates whether the entries returned should include attribute types only or both types and values. Default: False (both)
		:type types_only: bool
		:param size_limit: Size limit of result elements per query. Default: 1000
		:type size_limit: int
		:param derefAliases: Specifies the behavior on how aliases are dereferenced. Default: 0 (never)
		:type derefAliases: int
		:param timeLimit: Maximum time the search should take. If time limit reached the server SHOULD return an error
		:type timeLimit: int
		:param controls: additional controls to be passed in the query
		:type controls: List[class:`Control`]
		:param return_done: Controls wether the final 'done' LDAP message should be returned, or just the actual results
		:type return_done: bool

		:return: Async generator which yields (`LDAPMessage`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`LDAPMessage`, :class:`Exception`)]
		"""

		try:
			if self.status == MSLDAPClientStatus.CONNECTED:
				raise Exception('Connected, but not bound.')
			if self.status != MSLDAPClientStatus.RUNNING:
				raise Exception('Connection not running! Probably encountered an error')
		
			if timeLimit is None:
				timeLimit = 600 #not sure

			flt = query_syntax_converter(query)
			
			searchreq = {
				'baseObject' : base.encode(),
				'scope': search_scope,
				'derefAliases': derefAliases, 
				'sizeLimit': size_limit,
				'timeLimit': timeLimit,
				'typesOnly': types_only,
				'filter': flt,
				'attributes': attributes,
			}

			br = { 'searchRequest' : SearchRequest( searchreq	)}
			msg = { 'protocolOp' : protocolOp(br)}
			if controls is not None:
				msg['controls'] = controls

			msg_id = await self.send_message(msg)
			
			while True:
				results = await self.recv_message(msg_id)
				if len(results) > 0 and isinstance(results[0], Exception):
					raise results[0]
				
				for message in results:
					msg_type = message['protocolOp'].name
					message = message.native
					if msg_type == 'searchResDone':
						if return_done is True:
							yield (message, None)
						break
					
					elif msg_type == 'searchResRef':
						#TODO: Check if we need to deal with this further
						continue

					if return_done is True:
						yield (message, None)
					else:
						yield (convert_result(message['protocolOp']), None)
				else:
					continue
				
				break
		
		except Exception as e:
			yield (None, e)

	async def pagedsearch(self, base:str, query:str, attributes:List[bytes], search_scope:int = 2, size_limit:int = 1000, typesOnly:bool = False, derefAliases:bool = 0, timeLimit:int = None, controls:List[Control] = None, rate_limit:int = 0, raw: bool = False):
		"""
		Paged search is the same as the search operation and uses it under the hood. Adds automatic control to read all results in a paged manner.
		
		:param base: base tree on which the search should be performed
		:type base: str
		:param query: filter query that defines what should be searched for
		:type query: str
		:param attributes: a list of attributes to be included in the response
		:type attributes: List[bytes]
		:param search_scope: Specifies the search operation's scope. Default: 2 (Subtree)
		:type search_scope: int
		:param types_only: indicates whether the entries returned should include attribute types only or both types and values. Default: False (both)
		:type types_only: bool
		:param size_limit: Size limit of result elements per query. Default: 1000
		:type size_limit: int
		:param derefAliases: Specifies the behavior on how aliases are dereferenced. Default: 0 (never)
		:type derefAliases: int
		:param timeLimit: Maximum time the search should take. If time limit reached the server SHOULD return an error
		:type timeLimit: int
		:param controls: additional controls to be passed in the query
		:type controls: dict
		:param rate_limit: time to sleep between each query
		:type rate_limit: float
		:param raw: Return the attributes without conversion
		:type raw: bool

		:return: Async generator which yields (`dict`, None) tuple on success or (None, `Exception`) on error
		:rtype: Iterator[(:class:`dict`, :class:`Exception`)]
		"""
		
		try:
			if self.status == MSLDAPClientStatus.CONNECTED:
				raise Exception('Connected, but not bound.')
			if self.status != MSLDAPClientStatus.RUNNING:
				raise Exception('Connection not running! Probably encountered an error')
		
			cookie = b''
			while True:
				await asyncio.sleep(rate_limit)
				ctrl_list_temp = [
					Control({
						'controlType' : b'1.2.840.113556.1.4.319',
						'controlValue': SearchControlValue({
							'size' : size_limit,
							'cookie': cookie
						}).dump()
					})
				]
				if controls is not None:
					ctrl_list_temp.extend(controls)
				
				ctrs = Controls(
					ctrl_list_temp
				)


				async for res, err in self.search(
					base, 
					query, 
					attributes, 
					search_scope = search_scope, 
					size_limit=size_limit, 
					types_only=typesOnly, 
					derefAliases=derefAliases, 
					timeLimit=timeLimit, 
					controls = ctrs,
					return_done = True
					):
						if err is not None:
							yield (None, err)
							return
						
						if 'resultCode' in res['protocolOp']:
							if res['protocolOp']['resultCode'] != 'success':
								raise LDAPSearchException(res['protocolOp']['resultCode'], res['protocolOp']['diagnosticMessage'])
							for control in res['controls'] or []:
								if control['controlType'] == b'1.2.840.113556.1.4.319':
									try:
										cookie = SearchControlValue.load(control['controlValue']).native['cookie']
									except:
										logger.debug("Cookie missing in the response!")
										cookie = b''
									break
						else:
							yield (convert_result(res['protocolOp'], raw), None)

				if cookie == b'':
					break
		
		except Exception as e:
			yield (None, e)

	async def whoami(self):
		if self.status != MSLDAPClientStatus.RUNNING:
			return None, Exception('Connection not running! Probably encountered an error')
		
		ext = {
			'requestName': b'1.3.6.1.4.1.4203.1.11.3',
		}
		br = { 'extendedReq' : ExtendedRequest(ext)}
		msg = { 'protocolOp' : protocolOp(br)}

		msg_id = await self.send_message(msg)
		res = await self.recv_message(msg_id)
		res = res[0]
		if isinstance(res, Exception):
			return None, res
		if res.native['protocolOp']['resultCode'] != 'success':
			return False, LDAPBindException(
					res['protocolOp']['resultCode'], 
					res['protocolOp']['diagnosticMessage']
				)
		return res.native['protocolOp']['responseValue'].decode(), None
		


	async def get_serverinfo(self):
		if self.status not in [MSLDAPClientStatus.CONNECTED, MSLDAPClientStatus.RUNNING]:
			return None, Exception('Connection not running! Probably encountered an error')

		attributes = [
			b'subschemaSubentry',
    		b'dsServiceName',
    		b'namingContexts',
    		b'defaultNamingContext',
    		b'schemaNamingContext',
    		b'configurationNamingContext',
    		b'rootDomainNamingContext',
    		b'supportedControl',
    		b'supportedLDAPVersion',
    		b'supportedLDAPPolicies',
    		b'supportedSASLMechanisms',
    		b'dnsHostName',
    		b'ldapServiceName',
    		b'serverName',
    		b'supportedCapabilities'
		]

		filt = { 'present' : 'objectClass'.encode() }
		searchreq = {
			'baseObject' : b'',
			'scope': 0,
			'derefAliases': 0, 
			'sizeLimit': 1,
			'timeLimit': self.target.timeout - 1,
			'typesOnly': False,
			'filter': Filter(filt),
			'attributes': attributes,
		}

		br = { 'searchRequest' : SearchRequest( searchreq	)}
		msg = { 'protocolOp' : protocolOp(br)}

		msg_id = await self.send_message(msg)
		res = await self.recv_message(msg_id)
		res = res[0]
		if isinstance(res, Exception):
			return None, res
		
		if 'attributes' not in res.native['protocolOp']:
			return None, None
		return convert_attributes(res.native['protocolOp']['attributes']), None
