from unicrypto import hashlib
import datetime
from asn1crypto.core import OrderedDict

from kerbad.protocol.asn1_structs import EncryptedData, krb5_pvno, \
	PrincipalName, PrincipalName, Realm, Checksum, APOptions, Authenticator,\
	Ticket, AP_REQ, EncTicketPart, TicketFlags

from kerbad.protocol.encryption import _enctype_table, Key
from kerbad.protocol.constants import NAME_TYPE, MESSAGE_TYPE


# ---------------------------------------------------------------------------
# EncTicketPart crypto — the canonical decrypt / mutate / re-encrypt primitive.
#
# A Kerberos ticket's ``enc-part`` is encrypted with the OWNING account's key
# (key usage 2: AS-REP / TGS-REP ticket). Both offline ticket-mutation attacks
# in ADscan share this exact decrypt -> mutate -> re-encrypt dance:
#   * RBCD force-forwardable (kerbad ``getST``): flip the ``forwardable`` flag on
#     an S4U2Self ticket using the requesting account's long-term key.
#   * Child -> parent escalation (``raise_child_native``): inject an
#     Enterprise-Admins SID into the PAC of a child TGT using the child krbtgt
#     key.
# These helpers are the single source of truth for that primitive so neither
# call-site re-derives the cipher / key-usage by hand.
# ---------------------------------------------------------------------------


def decrypt_enc_ticket_part(enc_part: dict, key: Key) -> EncTicketPart:
	"""Decrypt a ticket's ``enc-part`` into an :class:`EncTicketPart`.

	Args:
		enc_part: The ticket's native ``enc-part`` dict (``ticket['enc-part']``),
			carrying ``etype`` and ``cipher``.
		key: The owning account's key (key usage 2 — the service/account key the
			ticket is encrypted with).
	"""
	cipher = _enctype_table[int(enc_part['etype'])]
	return EncTicketPart.load(cipher.decrypt(key, 2, enc_part['cipher']))


def encrypt_enc_ticket_part(etype, key: Key, enc_ticket_part: EncTicketPart) -> bytes:
	"""Re-encrypt a (mutated) :class:`EncTicketPart` and return the ciphertext.

	Use this when the caller rebuilds a fresh ticket/AS-REP envelope around the
	new ciphertext (e.g. ``raise_child_native``). ``etype`` is the ticket
	enc-part etype; ``key`` is the owning account's key (key usage 2).
	"""
	cipher = _enctype_table[int(etype)]
	return cipher.encrypt(key, 2, enc_ticket_part.dump(), None)


def reencrypt_enc_ticket_part(enc_part: dict, key: Key, enc_ticket_part: EncTicketPart) -> None:
	"""Re-encrypt a (mutated) :class:`EncTicketPart` back into ``enc_part`` IN PLACE.

	Inverse of :func:`decrypt_enc_ticket_part` (same key, key usage 2). The
	``cipher`` field of ``enc_part`` is overwritten with the new ciphertext. Use
	this when the caller keeps the same ticket object (e.g. the RBCD
	force-forwardable flip).
	"""
	enc_part['cipher'] = encrypt_enc_ticket_part(enc_part['etype'], key, enc_ticket_part)


def set_enc_ticket_part_flag(enc_ticket_part: EncTicketPart, flag: str) -> bool:
	"""Set a :class:`TicketFlags` flag (e.g. ``'forwardable'``) on an EncTicketPart in place.

	Returns ``True`` when the flag was newly added, ``False`` when it was already
	present (so the caller can skip a needless re-encrypt).
	"""
	flags = set(enc_ticket_part.native['flags'] or [])
	if flag in flags:
		return False
	flags.add(flag)
	enc_ticket_part['flags'] = TicketFlags(flags)
	return True

from kerbad.protocol.structures import AuthenticatorChecksum
from kerbad.gssapi.channelbindings import ChannelBindingsStruct

def construct_apreq_from_tgs_tgt(tgs, sessionkey, tgt, flags = None, seq_number = 0, ap_opts = [], cb_data = None, now=None):
	return construct_apreq_from_tgs(
		tgs,
		sessionkey,
		tgt['crealm'],
		tgt['cname'],
		flags,
		seq_number,
		ap_opts,
		cb_data,
		now=now
	)

def construct_apreq_from_tgs(tgs, sessionkey, crealm, cname, flags = None, seq_number = 0, ap_opts = [], cb_data = None, now=None):
	return construct_apreq_from_ticket(
		Ticket(tgs['ticket']).dump(),
		sessionkey,
		crealm,
		cname,
		flags,
		seq_number,
		ap_opts,
		cb_data,
		now=now
	)

def construct_apreq_from_ticket(ticket_data, sessionkey, crealm, cname, flags = None, seq_number = 0, ap_opts = [], cb_data = None, now=None):
	if now is None:
		now = datetime.datetime.now(datetime.timezone.utc)
	authenticator_data = {}
	authenticator_data['authenticator-vno'] = krb5_pvno
	if isinstance(crealm, Realm):
		authenticator_data['crealm'] = crealm
	else:
		authenticator_data['crealm'] = Realm(crealm)
	
	try:
		authenticator_data['cname'] = PrincipalName(cname)
	except:
		if isinstance(cname, PrincipalName):
			authenticator_data['cname'] = cname
		else:
			authenticator_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [cname]})
	
	authenticator_data['cusec'] = now.microsecond
	authenticator_data['ctime'] = now.replace(microsecond=0)
	if flags is not None:

		ac = AuthenticatorChecksum()
		ac.flags = flags
		ac.channel_binding = b'\x00'*16
		if cb_data is not None:
			cb_struct = ChannelBindingsStruct()
			cb_struct.application_data = cb_data
			ac.channel_binding = hashlib.md5(cb_struct.to_bytes()).digest()

		chksum = {}
		chksum['cksumtype'] = 0x8003
		chksum['checksum'] = ac.to_bytes()

		authenticator_data['cksum'] = Checksum(chksum)
		authenticator_data['seq-number'] = seq_number

	cipher = _enctype_table[sessionkey.enctype]
	authenticator_data_enc = cipher.encrypt(sessionkey, 11, Authenticator(authenticator_data).dump(), None)

	ap_req = {}
	ap_req['pvno'] = krb5_pvno
	ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
	ap_req['ticket'] = Ticket.load(ticket_data)
	ap_req['ap-options'] = APOptions(set(ap_opts))
	ap_req['authenticator'] = EncryptedData({'etype': sessionkey.enctype, 'cipher': authenticator_data_enc})
	return AP_REQ(ap_req).dump()