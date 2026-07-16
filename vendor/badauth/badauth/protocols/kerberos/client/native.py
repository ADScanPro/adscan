
import datetime

from badauth.protocols.kerberos import logger
from badauth.common.winapi.constants import ISC_REQ
from badauth.common.credentials.kerberos import KerberosCredential
from badauth.protocols.kerberos.gssapi import get_gssapi, KRB5_MECH_INDEP_TOKEN
from badauth.protocols.kerberos.gssapismb import get_gssapi as gssapi_smb

from kerbad.common.spn import KerberosSPN
from kerbad.gssapi.gssapi import GSSAPIFlags
from kerbad.protocol.asn1_structs import AP_REP, EncAPRepPart, Ticket, EncryptedData, KRB_ERROR
from kerbad.protocol.constants import MESSAGE_TYPE
from kerbad.protocol.ticketutils import construct_apreq_from_ticket
from kerbad.protocol.encryption import Key, _enctype_table
from kerbad.aioclient import AIOKerberosClient
from kerbad.protocol.errors import KerberosError, KerberosErrorCode


class KerberosClientNative:
	def __init__(self, credential:KerberosCredential):
		self.credential = credential
		self.ccred = self.credential.to_ccred()
		
		self.kc = None
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.seq_number = 0
		self.from_ccache = False
	
		self.flags = \
			GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		
	
	def get_seq_number(self):
		"""
		Returns the initial sequence number. It is 0 by default, but can be adjusted during authentication, 
		by passing the 'seq_number' parameter in the 'authenticate' function
		"""
		return self.seq_number
	
	def signing_needed(self):
		"""
		Checks if integrity protection was negotiated
		"""
		return GSSAPIFlags.GSS_C_INTEG_FLAG in self.flags
	
	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return GSSAPIFlags.GSS_C_CONF_FLAG in self.flags
				
	async def sign(self, data:bytes, message_no:int, direction = 'init', reset_cipher = False):
		"""
		Signs a message.

		The ``reset_cipher`` keyword is accepted (and ignored) for parity with
		the NTLM sign() signature so that SPNEGO/DCE-RPC callers that pass it
		uniformly do not blow up when the selected GSS context is Kerberos.
		Kerberos GSS_GetMIC is stateless wrt cipher reset, so this is a no-op.
		"""
		del reset_cipher  # no-op for Kerberos GSS_GetMIC; kept for SPNEGO parity
		return self.gssapi.GSS_GetMIC(data, message_no, direction = direction)
		
	async def encrypt(self, data:bytes, message_no:int, *args, **kwargs):
		"""
		Encrypts a message. 
		"""
		data, eeee  = self.gssapi.GSS_Wrap(data, message_no, *args, **kwargs)
		return data, eeee 
		
	async def decrypt(self, data:bytes, message_no:int, *args, **kwargs):
		"""
		Decrypts message. Also performs integrity checking.
		"""

		return self.gssapi.GSS_Unwrap(data, message_no, *args, **kwargs)
	
	def get_session_key(self):
		return self.session_key.contents

	def iscreq_to_gssapiflags(self, flags:ISC_REQ):
		if flags is None:
			return self.flags
		kflags = GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		if ISC_REQ.INTEGRITY in flags:
			kflags |= GSSAPIFlags.GSS_C_INTEG_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_INTEG_FLAG
		if ISC_REQ.CONFIDENTIALITY in flags:
			kflags |= GSSAPIFlags.GSS_C_CONF_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_CONF_FLAG
		if ISC_REQ.REPLAY_DETECT in flags:
			kflags |= GSSAPIFlags.GSS_C_REPLAY_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_REPLAY_FLAG
		if ISC_REQ.SEQUENCE_DETECT in flags:
			kflags |= GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		if ISC_REQ.USE_DCE_STYLE in flags:
			kflags |= GSSAPIFlags.GSS_C_DCE_STYLE
		else:
			kflags &= ~GSSAPIFlags.GSS_C_DCE_STYLE
		if ISC_REQ.MUTUAL_AUTH in flags:
			kflags |= GSSAPIFlags.GSS_C_MUTUAL_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_MUTUAL_FLAG
		return kflags
		
	
	async def authenticate(self, authData:bytes, flags:ISC_REQ = None, seq_number:int = 0, cb_data:bytes = None, spn:str = None, **kwargs):
		"""
		This function is called (multiple times depending on the flags) to perform authentication. 
		"""
		try:
			self.flags = self.iscreq_to_gssapiflags(flags)
			logger.debug('Flags: %s' % self.flags)
			

			if spn is None:
				raise Exception("SPN is needed for kerberos!")
			else:
				spn = KerberosSPN.from_spn(spn)

			logger.debug('SPN: %s' % spn)
			if self.kc is None:
				self.kc = AIOKerberosClient(self.ccred, self.credential.target)

			if self.iterations == 0:
				self.seq_number = 0
				self.iterations += 1
				
				try:
					#check TGS first, maybe ccache already has what we need
					# Guard: password/hash/aes credentials have no ccache (ccred.ccache
					# is None) — calling .list_targets() on None raised an AttributeError
					# that, while caught by the broad ``except`` below, masked the real
					# Kerberos failure (e.g. KDC_ERR_PREAUTH_FAILED) in tracebacks and
					# debug logs. Skip the ccache reuse check cleanly when there is no
					# ccache rather than relying on the exception path.
					if self.ccred.ccache is None:
						raise Exception('No CCACHE present for this credential; minting a fresh TGT')
					for target in self.ccred.ccache.list_targets():
						# just printing this to debug...
						logger.debug('CCACHE SPN record: %s' % target)

					# --- ADscan vendor fix: fresh-TGS gate (KRB_ERR_GENERIC) ---
					# When the credential ccache contains a TGT (a *generic* credential),
					# reusing a cached SERVICE ticket via tgs_from_ccache /
					# construct_apreq_from_ticket produced AP-REQs that the server
					# rejected with KRB_ERR_GENERIC, while the SAME ticket freshly minted
					# from the TGT worked. So when a TGT is present AND the requested SPN
					# is itself a real service (not the krbtgt), mint a FRESH service
					# ticket from the ccache TGT (get_TGS force_fresh_tgs=True contacts
					# the KDC and bypasses its cached-TGS short-circuit) instead of
					# reusing the cached service ticket.
					#
					# Scoped ccaches (S4U2Proxy / RBCD / silver) hold NO TGT — only the
					# one service ticket that IS the capability — so they keep reusing
					# that cached service ticket (ccache_has_tgt is False → gate off).
					# A request whose SPN is the krbtgt (spn_is_tgt) also keeps the
					# cached path: there is nothing fresher to mint.
					ccache_has_tgt = any(
						cred.server.to_string(separator='/').lower().find('krbtgt') != -1
						for cred in self.ccred.ccache.credentials
					)
					spn_is_tgt = (
						str(getattr(spn, 'service', '') or '').lower() == 'krbtgt'
					)
					# --- ADscan vendor fix: fresh-TGS gate is SAME-REALM only ---
					# The gate deliberately does NOT fire for a cross-realm credential
					# (cross_target/cross_realm set by get_client_newtarget for a
					# trusted/foreign forest). A cross-realm ccache holds only the AUTH
					# realm TGT; asking the AUTH KDC directly for a service SPN whose
					# realm is the TARGET realm returns the cross-realm REFERRAL TGT
					# (krbtgt/TARGET@AUTH, RC4 inter-realm key), NOT a usable service
					# ticket — presenting it to the target service yields
					# SEC_E_LOGON_DENIED. Cross-realm binds therefore fall through to the
					# ``else`` below (tgs_from_ccache raises 'No TGS found' for the
					# foreign SPN), into the ``except`` branch, which follows
					# cred.cross_target → get_referral_ticket → the correct target-realm
					# service ticket (the ONE existing referral path). Keeping that logic
					# here too would duplicate it; the gate stays single-responsibility
					# (same-realm fresh-TGS only).
					if ccache_has_tgt and not spn_is_tgt and self.credential.cross_target is None:
						logger.debug(
							'Fresh-TGS gate: TGT present in ccache and SPN is a service; '
							'minting a fresh service ticket instead of reusing a cached one.'
						)
						# Load the TGT from the ccache (get_TGT returns early when the
						# ccache already holds it), then force a fresh KDC round-trip.
						await self.kc.with_clock_skew(self.kc.get_TGT, override_etype = self.credential.etypes)
						# Defensive: a missing/literal-None SPN realm (the badldap
						# MSLDAPTarget built by get_client_newtarget has no domain →
						# to_target_string emits ldap/host@None) would make the KDC reject
						# the TGS-REQ. The gate is same-realm only here, so pin the SPN to
						# the credential's own realm.
						if str(getattr(spn, 'domain', None) or '').lower() in ('', 'none'):
							spn.domain = self.credential.domain
						tgs, encpart, self.session_key = await self.kc.with_clock_skew(
							self.kc.get_TGS, spn, force_fresh_tgs = True
						)
						self.from_ccache = False
					else:
						tgs, encpart, self.session_key, err = self.kc.tgs_from_ccache(spn)
						if err:
							raise err
						logger.debug('Got TGS from CCACHE!')
						self.from_ccache = True
				except:
					# fetching TGT
					try:
						tgt = await self.kc.with_clock_skew(self.kc.get_TGT, override_etype = self.credential.etypes)
					except KerberosError as e:
						if e.errorcode == KerberosErrorCode.KDC_ERR_WRONG_REALM:
							# if the target user is in a different domain, we need to get a referral ticket
							# however at this point it's a guess work, as this heavily relies on the target domain's trust settings
							# and the correct DNS settings

							newtarget = self.kc.target.get_kerberos_target(dc_ip=self.kc.credential.domain, domain=self.kc.credential.domain)
							newkc = AIOKerberosClient(self.ccred, newtarget)
							ref_tgs, ref_encpart, ref_key, new_factory = await newkc.with_clock_skew(newkc.get_referral_ticket, spn.domain, self.credential.target.get_ip_or_hostname())
							self.kc = new_factory.get_client()
							tgs, encpart, self.session_key = await self.kc.with_clock_skew(self.kc.get_TGS, spn)#, override_etype = self.preferred_etypes)						
						else:
							logger.debug('Failed to get TGT! %s' % e)
							raise e

					except Exception as e:
						raise e
					# if the target server is in a different domain, we need to get a referral ticket
					if self.credential.cross_target is not None:
						# cross-domain kerberos
						ref_tgs, ref_encpart, ref_key, new_factory = await self.kc.with_clock_skew(self.kc.get_referral_ticket, self.credential.cross_realm, self.credential.cross_target.get_ip_or_hostname())
						self.kc = new_factory.get_client()
						spn.domain = self.credential.cross_realm
					tgs, encpart, self.session_key = await self.kc.with_clock_skew(self.kc.get_TGS, spn)#, override_etype = self.preferred_etypes)
				
				# ADSCAN: do NOT dump the full TGS/encpart/session-key — they
				# contain the encrypted ticket cipher and the raw Kerberos
				# session key (sensitive), and are now bridged to telemetry at
				# DEBUG. Log only a non-sensitive marker.
				logger.debug('TGS acquired (session key etype=%s)' % getattr(self.session_key, 'enctype', '?'))

				ap_opts = []
				if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags or GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags:
						ap_opts.append('mutual-required')
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(
							tgs, 
							encpart, 
							self.session_key, 
							flags = self.flags, 
							seq_number = self.seq_number, 
							ap_opts=ap_opts, 
							cb_data = cb_data
						)
					else:
						apreq = construct_apreq_from_ticket(
							Ticket(tgs['ticket']).dump(),
							self.session_key,
							tgs['crealm'],
							tgs['cname']['name-string'][0],
							flags = self.flags,
							seq_number = self.seq_number,
							ap_opts = ap_opts,
							cb_data = cb_data,
							now = self.kc._now(),
						)

					logger.debug('APREQ constructed')  # ADSCAN: do not dump raw AP-REQ bytes
					return apreq, True, None

				else:
					#not mutual nor dce auth will take one step only
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(
							tgs,
							encpart,
							self.session_key,
							flags = self.flags,
							seq_number = self.seq_number,
							ap_opts=ap_opts,
							cb_data = cb_data)
					else:
						apreq = construct_apreq_from_ticket(
							Ticket(tgs['ticket']).dump(),
							self.session_key,
							tgs['crealm'],
							tgs['cname']['name-string'][0],
							flags = self.flags,
							seq_number = self.seq_number,
							ap_opts = ap_opts,
							cb_data = cb_data,
							now = self.kc._now(),
						)
					
					logger.debug('APREQ constructed')  # ADSCAN: do not dump raw AP-REQ bytes
					self.gssapi = get_gssapi(self.session_key)
					return apreq, False, None

			else:
				self.seq_number = seq_number

				logger.debug('Processing AP_REP')  # ADSCAN: do not dump raw AP_REP bytes
				try:
					temp = KRB5_MECH_INDEP_TOKEN.from_bytes(authData)
					# The 2-byte inner token-type prefix (RFC 1964 §1.1) tells us what the
					# server actually sent in the AP exchange:
					#   \x02\x00 = KRB_AP_REP  (mutual-auth reply — the happy path)
					#   \x03\x00 = KRB_ERROR   (the server rejected the AP-REQ)
					# A wrapped KRB-ERROR (APPLICATION 30 / 0x7e) is NOT an AP-REP
					# (APPLICATION 15 / 0x6f). Blindly calling AP_REP.load() on it dies with
					# an opaque ASN.1 tag error and DESTROYS the real Kerberos error-code, so
					# downstream code misdiagnoses every wrapped error as a wrong-SPN bind.
					# Branch on the token-type so the genuine error-code (etype/salt/skew/SPN)
					# survives and the posture/recovery seams can act on it.
					token_id = temp.data[:2]
					if token_id == b'\x03\x00':
						# KRB_ERROR — propagate the real Kerberos error-code instead of
						# corrupting it through an AP-REP parse.
						krberr = KRB_ERROR.load(temp.data[2:])
						logger.debug(
							'AP exchange returned a wrapped KRB-ERROR error-code=%s'
							% int(krberr.native.get('error-code', -1))
						)
						raise KerberosError(krberr, 'AP exchange rejected by server')
					elif token_id == b'\x02\x00':
						aprep = AP_REP.load(temp.data[2:]).native
					else:
						# Unexpected inner token-type — surface it explicitly rather than
						# guessing it is an AP-REP and dying with an opaque tag error.
						try:
							aprep = AP_REP.load(temp.data[2:]).native
						except Exception:
							# Some hosts omit the 2-byte token-type prefix inside the GSSAPI
							# wrapper; try without skipping it before falling back.
							logger.debug('AP_REP load with [2:] failed, retrying without offset (token-id=0x%s)' % token_id.hex())  # ADSCAN: do not dump raw AP_REP bytes
							aprep = AP_REP.load(temp.data).native
				except KerberosError:
					# A genuine, fully-decoded Kerberos error — re-raise as-is so the
					# real error-code reaches the outer handler / recovery layer.
					raise
				except Exception as e:
					# KRB5_MECH_INDEP_TOKEN.from_bytes() failed — happens on Windows 10
					# workstations that wrap the AP-REP in a GSSAPI token whose OID the
					# parser cannot handle (ObjectIdentifier.load fails on the inner OID).
					# The outer byte is still 0x60 (GSSAPI APPLICATION tag 0).
					#
					# Strategy: if the data starts with 0x60, scan the first 256 bytes for
					# the AP-REP APPLICATION tag 0x6f (APPLICATION CONSTRUCTED 15) and try
					# to parse from each candidate offset.  This extracts the raw AP-REP
					# that Windows 10 embeds inside the GSSAPI wrapper without re-implementing
					# the full GSSAPI/SPNEGO parser.
					logger.debug('AP_REP fallback: GSSAPI parse error=%s' % e)  # ADSCAN: do not dump raw AP_REP bytes
					aprep = None
					if authData and authData[0:1] == b'\x60':
						search_window = authData[:256]
						for offset in range(1, len(search_window)):
							if search_window[offset:offset+1] == b'\x6f':
								try:
									aprep = AP_REP.load(authData[offset:]).native
									logger.debug('AP_REP extracted from GSSAPI wrapper at offset=%d' % offset)
									break
								except Exception:
									continue
					if aprep is None:
						# Before the blind AP_REP.load, the GSSAPI wrapper the earlier
						# branches couldn't decode may still be carrying a KRB-ERROR
						# (APPLICATION 30 / 0x7e) rather than an AP-REP (APPLICATION 15 /
						# 0x6f) — the 0x6f scan above would not have matched it. Mirror the
						# token-id 0x0300 branch above: scan for the KRB-ERROR tag, decode
						# it and raise the REAL Kerberos error-code instead of corrupting it
						# through an AP-REP parse.
						if authData and authData[0:1] == b'\x60':
							search_window = authData[:256]
							for offset in range(1, len(search_window)):
								if search_window[offset:offset+1] == b'\x7e':
									try:
										krberr = KRB_ERROR.load(authData[offset:])
										logger.debug(
											'AP exchange returned a wrapped KRB-ERROR error-code=%s'
											% int(krberr.native.get('error-code', -1))
										)
										raise KerberosError(krberr, 'AP exchange rejected by server')
									except KerberosError:
										raise
									except Exception:
										continue
						# Final fallback: raw bytes (will fail with original error if still 0x60)
						try:
							aprep = AP_REP.load(authData).native
						except Exception as parse_exc:
							# Do NOT double-wrap: if the inner error is already an
							# 'Error parsing ...AP_REP' wrap, re-raise it as-is so the real
							# Kerberos error survives instead of being buried under a second
							# identical wrapper.
							if str(parse_exc).startswith('Error parsing'):
								raise
							raise Exception(
								'Error parsing %s.AP_REP - %s'  # ADSCAN: do not include raw AP_REP bytes in the error
								% (AP_REP.__module__, parse_exc)
							) from parse_exc
				
				logger.debug('AP_REP parsed')  # ADSCAN: do not dump parsed AP_REP (enc-part cipher)
				cipher = _enctype_table[int(aprep['enc-part']['etype'])]()
				cipher_text = aprep['enc-part']['cipher']
				temp = cipher.decrypt(self.session_key, 12, cipher_text)
				
				enc_part = EncAPRepPart.load(temp).native
				cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
					
				now = self.kc._now()
				apreppart_data = {}
				apreppart_data['cusec'] = now.microsecond
				apreppart_data['ctime'] = now.replace(microsecond=0)
				apreppart_data['seq-number'] = enc_part['seq-number']
				#print('seq %s' % enc_part['seq-number'])
				#self.seq_number = 0 #enc_part['seq-number']
				
				# ADSCAN: apreppart_data carries subkey material — do not dump.
				apreppart_data_enc = cipher.encrypt(self.session_key, 12, EncAPRepPart(apreppart_data).dump(), None)

				#overriding current session key
				self.session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])

				logger.debug('mutual-auth subkey derived (etype=%s)' % getattr(self.session_key, 'enctype', '?'))  # ADSCAN: do not dump the session key

				ap_rep = {}
				ap_rep['pvno'] = 5 
				ap_rep['msg-type'] = MESSAGE_TYPE.KRB_AP_REP.value
				ap_rep['enc-part'] = EncryptedData({'etype': self.session_key.enctype, 'cipher': apreppart_data_enc}) 
				
				logger.debug('AP_REP (mutual-auth) constructed')  # ADSCAN: do not dump AP_REP (enc-part cipher)
				token = AP_REP(ap_rep).dump()
				if GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					self.gssapi = gssapi_smb(self.session_key)
				else:
					self.gssapi = get_gssapi(self.session_key)
				self.iterations += 1
				return token, True, None
		
		except Exception as e:
			return None, None, e
