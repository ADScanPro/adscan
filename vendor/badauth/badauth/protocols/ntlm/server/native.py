import copy
import os
import struct
from typing import cast, Callable
from badauth.common.winapi.constants import ISC_REQ
from badauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol


from unicrypto import hmac
from unicrypto import hashlib
from unicrypto.symmetric import RC4

from badauth.protocols.ntlm import logger
from badauth.common.credentials.ntlm import NTLMCredential
from badauth.protocols.ntlm.structures.serverinfo import NTLMServerInfo
from badauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from badauth.protocols.ntlm.structures.ntlmssp_message_signature import NTLMSSP_MESSAGE_SIGNATURE
from badauth.protocols.ntlm.structures.ntlmssp_message_signature_noext import NTLMSSP_MESSAGE_SIGNATURE_NOEXT
from badauth.protocols.ntlm.messages.negotiate import NTLMNegotiate
from badauth.protocols.ntlm.messages.challenge import NTLMChallenge
from badauth.protocols.ntlm.messages.authenticate import NTLMAuthenticate
from badauth.protocols.ntlm.creds_calc import netntlmv2, AVPAIRType, LMResponse, netntlm, netntlm_ess
from kerbad.gssapi.channelbindings import ChannelBindingsStruct
from badauth.protocols.ntlm.structures.avpair import AVPairs, MsvAvFlags
from badauth.protocols.ntlm.structures.version import Version
from badauth.protocols.ntlm.structures.serverinfo import FILETIME
from datetime import datetime
		

class NTLMServerNative:
	def __init__(self, credential:NTLMCredential):
		self.credential = credential
		self.challenge = credential.challenge if credential.challenge is not None else os.urandom(8)
		
		self.ntlmNegotiate     = None #ntlm Negotiate message from client
		self.ntlmChallenge     = None #ntlm Challenge message to client
		self.ntlmAuthenticate  = None #ntlm Authenticate message from client
		
		self.ntlmNegotiate_raw     = None #message as bytes, as it's recieved/sent
		self.ntlmChallenge_raw     = None #message as bytes, as it's recieved/sent
		self.ntlmAuthenticate_raw  = None #message as bytes, as it's recieved/sent

		
		self.EncryptedRandomSessionKey = None
		self.RandomSessionKey = credential.session_key if credential.session_key is not None else os.urandom(16)
		self.SessionBaseKey = None
		self.KeyExchangeKey = None
		
		self.SignKey_client = None
		self.SealKey_client = None
		self.SignKey_server = None
		self.SealKey_server = None

		self.crypthandle_client = None
		self.crypthandle_server = None
		
		self.seq_number = 0
		self.iteration_cnt = 0
		self.ntlm_credentials = None
		self.timestamp = credential.timestamp #used in unittest only!
		self.extra_info = None
			
	def load_negotiate(self, data):
		logger.debug('Loading negotiate message')
		self.ntlmNegotiate = NTLMNegotiate.from_bytes(data)
	
	def load_challenge(self, data):
		logger.debug('Loading challenge message')
		self.ntlmChallenge = NTLMChallenge.from_bytes(data)
		
	def load_authenticate(self, data):
		logger.debug('Loading authenticate message')
		self.ntlmAuthenticate = NTLMAuthenticate.from_bytes(data)
		
	def load_sessionkey(self, data):
		logger.debug('Loading sessionkey')
		self.RandomSessionKey = data
		self.setup_crypto(True)
	
	def is_guest(self):
		return self.credential.is_guest

	def get_seq_number(self):
		return self.seq_number
	
	def set_sign(self, tf = True):
		if tf == True:
			self.credential.flags |= NegotiateFlags.NEGOTIATE_SIGN
		else:
			self.credential.flags &= ~NegotiateFlags.NEGOTIATE_SIGN
			
	def set_seal(self, tf = True):
		if tf == True:
			self.credential.flags |= NegotiateFlags.NEGOTIATE_SEAL
		else:
			self.credential.flags &= ~NegotiateFlags.NEGOTIATE_SEAL
			
	def set_version(self, tf = True):
		if tf == True:
			self.credential.flags |= NegotiateFlags.NEGOTIATE_VERSION
		else:
			self.credential.flags &= ~NegotiateFlags.NEGOTIATE_VERSION
			
	def is_extended_security(self):
		return NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags
	
	def get_extra_info(self):
		self.extra_info = NTLMServerInfo.from_challenge(self.ntlmChallenge)
		return self.extra_info
		
	def MAC(self, handle, signingKey, seqNum, message):
		if self.is_extended_security() == True:
			msg = NTLMSSP_MESSAGE_SIGNATURE()
			if NegotiateFlags.NEGOTIATE_KEY_EXCH in self.ntlmChallenge.NegotiateFlags:
				tt = struct.pack('<i', seqNum) + message
				t = hmac.new(signingKey, digestmod='md5')
				t.update(tt)
				
				msg.Checksum = handle(t.digest()[:8])
				msg.SeqNum = seqNum
				seqNum += 1
			else:
				t = hmac.new(signingKey, digestmod='md5')
				t.update(struct.pack('<i',seqNum)+message)
				msg.Checksum = t.digest()[:8]
				msg.SeqNum = seqNum
				seqNum += 1
				
		else:
			raise Exception('Not implemented!')
			#t = struct.pack('<I',binascii.crc32(message)& 0xFFFFFFFF)
			#randompad = 0
			#msg = NTLMSSP_MESSAGE_SIGNATURE_NOEXT()
			#msg.RandomPad = handle(struct.pack('<I',randompad))
			#msg.Checksum = struct.unpack('<I',handle(messageSignature['Checksum']))[0]
			
		return msg.to_bytes()

	async def encrypt(self, data, sequence_no):
		"""
		This function is to support SSPI encryption.
		"""
		data = self.SEAL(
			self.SignKey_client,
			self.SealKey_client, 
			data,
			data,
			sequence_no, 
			self.crypthandle_client.encrypt
		)
		return data

	async def decrypt(self, data, sequence_no, direction='init', auth_data=None):
		"""
		This function is to support SSPI decryption.
		"""
		edata = data[16:]
		srv_sig = NTLMSSP_MESSAGE_SIGNATURE.from_bytes(data[:16])
		sealedMessage = self.crypthandle_server.encrypt(edata)
		signature = self.MAC(self.crypthandle_server.encrypt, self.SignKey_server, srv_sig.SeqNum, sealedMessage)
		#print('seqno     %s' % sequence_no)
		#print('Srv  sig: %s' % data[:16])
		#print('Calc sig: %s' % signature)

		return sealedMessage, None

	async def sign(self, data, message_no, direction=None, reset_cipher = False):
		"""
		Singing outgoing messages. The reset_cipher parameter is needed for calculating mechListMIC. 
		"""
		#print('sign data : %s' % data)
		#print('sign message_no : %s' % message_no)
		#print('sign direction : %s' % direction)
		signature = self.MAC(self.crypthandle_client.encrypt, self.SignKey_client, message_no, data)
		if reset_cipher is True:
			self.crypthandle_client = RC4(self.SealKey_client)
			self.crypthandle_server = RC4(self.SealKey_server)
		self.seq_number += 1
		return signature

	async def verify(self, data, signature):
		"""
		Verifying incoming server message
		"""
		signature_struct = NTLMSSP_MESSAGE_SIGNATURE.from_bytes(signature)
		calc_sig = self.MAC(self.crypthandle_server.encrypt, self.SignKey_server, signature_struct.SeqNum, data)
		#print('server signature    : %s' % signature)
		#print('calculates signature: %s' % calc_sig)
		return signature == calc_sig

	def SEAL(self, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt):
		"""
		This is the official SEAL function.
		"""
		sealedMessage = cipher_encrypt(messageToEncrypt)
		signature = self.MAC(cipher_encrypt, signingKey, seqNum, messageToSign)
		return sealedMessage, signature
		
	def SIGN(self, signingKey, message, seqNum, cipher_encrypt):
		"""
		This is the official SIGN function.
		"""
		return self.MAC(cipher_encrypt, signingKey, seqNum, message)
	
	def signing_needed(self):
		return (
			NegotiateFlags.NEGOTIATE_SIGN in self.ntlmChallenge.NegotiateFlags or \
			NegotiateFlags.NEGOTIATE_SEAL in self.ntlmChallenge.NegotiateFlags
		)
	
	def encryption_needed(self):
		return NegotiateFlags.NEGOTIATE_SEAL in self.ntlmChallenge.NegotiateFlags

	def calc_sealkey(self, mode = 'Client'):
		if NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags:
			if NegotiateFlags.NEGOTIATE_128 in self.ntlmChallenge.NegotiateFlags:
				sealkey = self.RandomSessionKey
			elif NegotiateFlags.NEGOTIATE_56 in self.ntlmChallenge.NegotiateFlags:
				sealkey = self.RandomSessionKey[:7]
			else:
				sealkey = self.RandomSessionKey[:5]
				
			if mode == 'Client':
				md5 = hashlib.new('md5')
				md5.update(sealkey + b'session key to client-to-server sealing key magic constant\x00')
				sealkey = md5.digest()
			else:
				md5 = hashlib.new('md5')
				md5.update(sealkey + b'session key to server-to-client sealing key magic constant\x00')
				sealkey = md5.digest()
				
		elif NegotiateFlags.NEGOTIATE_56 in self.ntlmChallenge.NegotiateFlags:
			sealkey = self.RandomSessionKey[:7] + b'\xa0'
		else:
			sealkey = self.RandomSessionKey[:5] + b'\xe5\x38\xb0'
			
		if mode == 'Client':
			self.SealKey_client = sealkey
			if sealkey is not None:
				self.crypthandle_client = RC4(self.SealKey_client)
		else:
			self.SealKey_server = sealkey
			if sealkey is not None:
				self.crypthandle_server = RC4(self.SealKey_server)
		
		if sealkey is not None:
			logger.debug('Setting %s sealkey' % mode)  # ADSCAN: do not dump raw sealkey hex
		return sealkey
		
	def calc_signkey(self, mode = 'Client'):
		if NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags:
			if mode == 'Client':
				md5 = hashlib.new('md5')
				md5.update(self.RandomSessionKey + b"session key to client-to-server signing key magic constant\x00")
				signkey = md5.digest()
			else:
				md5 = hashlib.new('md5')
				md5.update(self.RandomSessionKey + b"session key to server-to-client signing key magic constant\x00")
				signkey = md5.digest()
		else:
			signkey = None
			
		if mode == 'Client':
			if signkey is not None:
				logger.debug('Setting client signkey')  # ADSCAN: do not dump raw signkey hex
			self.SignKey_client = signkey

		else:
			if signkey is not None:
				logger.debug('Setting server signkey')  # ADSCAN: do not dump raw signkey hex
			self.SignKey_server = signkey
		
		return signkey
		
	def get_session_key(self):
		return self.RandomSessionKey
		
	def get_sealkey(self, mode = 'Client'):
		if mode == 'Client':
			return self.SealKey_client
		else:
			return self.SealKey_server
			
	def get_signkey(self, mode = 'Client'):
		if mode == 'Client':
			return self.SignKey_client
		else:
			return self.SignKey_server
		
	def setup_crypto(self, is_remote = False):
		logger.debug('Setting up crypto')
		if not self.RandomSessionKey:
			self.RandomSessionKey = os.urandom(16)
			logger.debug('RandomSessionKey generated')  # ADSCAN: do not dump raw session key hex
		
		
		if self.credential.is_guest == True:
			self.SessionBaseKey = b'\x00' * 16
			self.KeyExchangeKey = b'\x00' * 16
				
			rc4 = RC4(self.KeyExchangeKey)
			self.EncryptedRandomSessionKey = rc4.encrypt(self.RandomSessionKey)
			logger.debug('EncryptedRandomSessionKey computed')  # ADSCAN: do not dump raw key hex

		else:
			if is_remote is False:
				#this check is here to provide the option to load the messages + the sessionbasekey manually
				#then you will be able to use the sign and seal functions provided by this class
				self.SessionBaseKey = self.ntlm_credentials.SessionBaseKey
			
				rc4 = RC4(self.KeyExchangeKey)
				self.EncryptedRandomSessionKey = rc4.encrypt(self.RandomSessionKey)
				logger.debug('EncryptedRandomSessionKey computed')  # ADSCAN: do not dump raw key hex
		
		self.calc_sealkey('Client')
		self.calc_sealkey('Server')
		self.calc_signkey('Client')
		self.calc_signkey('Server')

	def isc_to_ntlm_flags(self, flags):
		# trying to guess what ISC flags match which
		if isinstance(flags, NegotiateFlags) is True:
			return flags
		if flags is None:
			# using the pre-defined flags
			return self.credential.flags
		ntlmflags = copy.deepcopy(self.credential.flags)
		ntlmflags |= NegotiateFlags.NEGOTIATE_56
		ntlmflags |= NegotiateFlags.NEGOTIATE_KEY_EXCH
		ntlmflags |= NegotiateFlags.NEGOTIATE_128
		ntlmflags |= NegotiateFlags.NEGOTIATE_VERSION
		ntlmflags |= NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY
		ntlmflags |= NegotiateFlags.NEGOTIATE_NTLM
		ntlmflags |= NegotiateFlags.NEGOTIATE_LM_KEY
		ntlmflags |= NegotiateFlags.REQUEST_TARGET
		ntlmflags |= NegotiateFlags.NTLM_NEGOTIATE_OEM
		ntlmflags |= NegotiateFlags.NEGOTIATE_UNICODE
		ntlmflags &= ~NegotiateFlags.TARGET_TYPE_SERVER
		
		if ISC_REQ.INTEGRITY in flags:
			ntlmflags |= NegotiateFlags.NEGOTIATE_SIGN
		else:
			ntlmflags  &= ~NegotiateFlags.NEGOTIATE_SIGN

		
		if ISC_REQ.CONFIDENTIALITY in flags:
			ntlmflags |= NegotiateFlags.NEGOTIATE_SEAL
		else:
			ntlmflags  &= ~NegotiateFlags.NEGOTIATE_SEAL
		
		return ntlmflags

	async def authenticate_server(self, authData, flags = None, cb_data = None, spn=None, **kwargs):
		# check if kwargs have target info
		target = None
		try:
			if 'target' in kwargs:
				from asysocks.unicomm.common.target import UniTarget
				target = cast(UniTarget, kwargs['target'])
		except:
			pass
			
		flags = self.isc_to_ntlm_flags(flags)
		logger.debug('Flags: %s' % flags)
		if self.iteration_cnt == 0:
			if authData is None:
				raise Exception('First call as server MUST be with data!')
				
			self.iteration_cnt += 1
			#negotiate message was already calulcated in setup
			self.ntlmNegotiate = NTLMNegotiate.from_bytes(authData)
			self.ntlmNegotiate_raw = authData

			targetinfo = AVPairs()
			targetinfo[AVPAIRType.MsvAvNbDomainName] = 'TEST'
			targetinfo[AVPAIRType.MsvAvNbComputerName] = 'TEST$'

			targetinfo[AVPAIRType.MsvAvDnsDomainName] = 'TEST.local'
			targetinfo[AVPAIRType.MsvAvDnsComputerName] = 'TEST.local'
			targetinfo[AVPAIRType.MsvAvDnsTreeName] = 'TEST.local'
			targetinfo[AVPAIRType.MsvAvTimestamp] = FILETIME.from_datetime(datetime.now()).to_bytes()
			#targetinfo[AVPAIRType.MsvAvFlags] = MsvAvFlags.MsvAvFlags(0x00000002)
			

			flags = copy.deepcopy(self.ntlmNegotiate.NegotiateFlags)
			flags |= NegotiateFlags.NEGOTIATE_VERSION
			flags |= NegotiateFlags.NEGOTIATE_TARGET_INFO
			flags &= ~NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
			flags &= ~NegotiateFlags.NEGOTIATE_SEAL
			flags &= ~NegotiateFlags.NEGOTIATE_SIGN
			flags &= ~NegotiateFlags.TARGET_TYPE_SERVER

			# ADSCAN: NTLMv1 downgrade-capture mode (Responder --disable-ess parity).
			# When the capture credential requests a downgrade, clear Extended Session
			# Security so a v1-capable client returns a plain NetNTLMv1 (rainbow-crackable
			# via crack.sh with the fixed 1122334455667788 server challenge) instead of the
			# non-rainbow-crackable NTLMv1-ESS. Absent/False attr => unchanged (ESS stays on).
			if getattr(self.credential, 'force_ntlm_downgrade', False):
				flags &= ~NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY

			self.ntlmChallenge = NTLMChallenge.construct(
				# ADSCAN: use the server's configured challenge. ``self.challenge`` honors
				# ``credential.challenge`` (default random os.urandom(8) at __init__). This
				# was previously hardcoded ``os.urandom(8)`` here, which silently ignored any
				# configured fixed challenge — the bug that made a fixed 1122334455667788
				# downgrade challenge impossible. Default path is byte-identical (still random).
				challenge = self.challenge,
				targetName = self.credential.negotiate_domain if self.credential.negotiate_domain is not None else '',
				targetInfo = targetinfo,
				version = self.credential.negotiate_version,
				flags = flags
			)
			
			logger.debug('Negotiate message constructed')  # ADSCAN: do not dump full NTLM message
			self.ntlmChallenge_raw = self.ntlmChallenge.to_bytes()
			return self.ntlmChallenge_raw, True, None
			
		else:
			#client authenticate incoming
			self.ntlmAuthenticate_raw = authData
			self.ntlmAuthenticate = NTLMAuthenticate.from_bytes(authData)
			logger.debug('Authenticate message received')  # ADSCAN: do not dump full NTLM message
				
			##################flags = self.ntlmChallenge.NegotiateFlags
				
			#we need to calculate the response based on the credential and the settings flags
			if self.credential.ntlm_version == 1:
				return None, False, None
				#raise NotImplementedError('NTLMv1 is not supported as server!')
				logger.debug('NTLMv1 is used here')
				#NTLMv1 authentication
				# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
					
				#check if we authenticate as guest
				if self.credential.is_guest == True:
					logger.debug('NTLMv1 Guest authentication')
					lmresp = LMResponse()
					self.set_version(False)
					lmresp.Response = b'\x00'
					self.ntlmAuthenticate = NTLMAuthenticate.construct(
						flags,
						lm_response= lmresp,
						mic=None,
						encrypted_session = self.EncryptedRandomSessionKey,
						workstationname=target.hostname if target is not None else None
					)
					logger.debug('NTLMv1 Guest - NTLMAuthenticate constructed')  # ADSCAN: do not dump response hash
					return self.ntlmAuthenticate.to_bytes(), False, None
						
				if flags & NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY:
					logger.debug('NTLMv1 with extended security')
					self.ntlm_credentials = netntlm_ess.construct(self.ntlmChallenge.ServerChallenge, self.challenge, self.credential)
					
					self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key()
					self.setup_crypto()
						
					self.ntlmAuthenticate = NTLMAuthenticate.construct(
						flags,
						lm_response= self.ntlm_credentials.LMResponse,
						nt_response = self.ntlm_credentials.NTResponse,
						version = self.ntlmNegotiate.Version,
						encrypted_session = self.EncryptedRandomSessionKey,
						workstationname=target.hostname if target is not None else None
					)
					logger.debug('NTLMv1 with extended security - NTLMAuthenticate constructed')  # ADSCAN: do not dump response hash
				else:
					self.ntlm_credentials = netntlm.construct(self.ntlmChallenge.ServerChallenge, self.credential)
						
					self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key(with_lm = flags & NegotiateFlags.NEGOTIATE_LM_KEY, non_nt_session_key = flags & NegotiateFlags.REQUEST_NON_NT_SESSION_KEY)						
					self.setup_crypto()
					self.ntlmAuthenticate = NTLMAuthenticate.construct(
						flags,
						lm_response= self.ntlm_credentials.LMResponse,
						nt_response = self.ntlm_credentials.NTResponse,
						version = self.ntlmNegotiate.Version,
						encrypted_session = self.EncryptedRandomSessionKey,
						workstationname=target.hostname if target is not None else None
					)
					logger.debug('NTLMv1 - NTLMAuthenticate constructed')  # ADSCAN: do not dump response hash
							
							
			else:
				#NTLMv2
				# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
				if self.ntlmAuthenticate.UserName == '':
					# allowing guests here
					return None, False, None
					#lmresp = LMResponse()
					#lmresp.Response = b'\x00'
					#self.set_version(False)
					#self.setup_crypto()
					#self.ntlmAuthenticate = NTLMAuthenticate.construct(
					#	flags,
					#	lm_response= lmresp,
					#	encrypted_session = self.EncryptedRandomSessionKey,
					#	workstationname=target.hostname if target is not None else None
					#)						
					#logger.debug('NTLMv2 Guest - NTLMAuthenticate constructed')  # ADSCAN: do not dump response hash
					#return self.ntlmAuthenticate.to_bytes(), False, None
						
				else:
					return None, False, None
					#comment this out for testing!
					ti = self.ntlmChallenge.TargetInfo
					if spn is not None:
						ti[AVPAIRType.MsvAvTargetName] = spn
					if cb_data is not None:
						cb_struct = ChannelBindingsStruct()
						cb_struct.application_data = cb_data

						md5_ctx = hashlib.new('md5')
						md5_ctx.update(cb_struct.to_bytes())
						ti[AVPAIRType.MsvChannelBindings] = md5_ctx.digest()
					###
						
					self.ntlm_credentials = netntlmv2.construct(self.ntlmChallenge.ServerChallenge, self.challenge, ti, self.credential, timestamp = self.timestamp)
					self.KeyExchangeKey = self.ntlm_credentials.calc_key_exchange_key()
					logger.debug('NTLMv2 - KeyExchangeKey derived')  # ADSCAN: do not dump raw key hex				
					self.setup_crypto()
						
					#TODO: if "ti" / targetinfo in the challenge message has "MsvAvFlags" type and the bit for MIC is set (0x00000002) we need to send a MIC. probably...
					mic = None
						
					self.ntlmAuthenticate = NTLMAuthenticate.construct(
						flags,
						domainname= self.credential.domain,
						workstationname=target.hostname if target is not None else None,
						username= self.credential.username,
						lm_response= self.ntlm_credentials.LMResponse,
						nt_response= self.ntlm_credentials.NTResponse,
						version = self.ntlmNegotiate.Version,
						encrypted_session = self.EncryptedRandomSessionKey,
						mic = mic,
					)
				
					logger.debug('NTLMv2 - NTLMAuthenticate constructed')  # ADSCAN: do not dump response hash
			self.ntlmAuthenticate_raw = self.ntlmAuthenticate.to_bytes()
			return self.ntlmAuthenticate_raw, False, None
	
def ntlmserver_factory(ntlm_credential_factory: Callable = None) -> NTLMServerNative:
	if ntlm_credential_factory is None:
		ntlm_settings = NTLMCredential(
			'test',
			'test',
			'test',
			stype = asyauthSecret.PASSWORD
		)
	else:
		ntlm_settings = ntlm_credential_factory()
	ntlm_ctx = NTLMServerNative(ntlm_settings)
	return ntlm_ctx