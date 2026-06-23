import os
import io
import datetime
import glob
import base64
from typing import List

from kerbad.protocol.asn1_structs import Ticket, EncryptedData, \
	krb5_pvno, KrbCredInfo, EncryptionKey, KRBCRED, TicketFlags, EncKrbCredPart
from kerbad.common.utils import dt_to_kerbtime
from kerbad.protocol.constants import EncryptionType, MESSAGE_TYPE
from kerbad import logger
from asn1crypto import core
from unicrypto import hashlib
from kerbad.common.kirbi import Kirbi
from kerbad.common.spn import KerberosSPN



# http://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
class Header:
	def __init__(self):
		self.tag:int = None
		self.taglen:int = None
		self.tagdata:bytes = None
		
	@staticmethod
	def parse(data):
		"""
		returns a list of header tags
		"""
		reader = io.BytesIO(data)
		headers = []
		while reader.tell() < len(data):
			h = Header()
			h.tag = int.from_bytes(reader.read(2), byteorder='big', signed=False)
			h.taglen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
			h.tagdata = reader.read(h.taglen)
			headers.append(h)
		return headers
		
	def to_bytes(self):
		t =  self.tag.to_bytes(2, byteorder='big', signed=False)
		t += len(self.tagdata).to_bytes(2, byteorder='big', signed=False)
		t += self.tagdata
		return t
	
	@staticmethod
	def from_bytes(data:bytes):
		return Header.parse(data)
		
	def __str__(self):
		t = 'tag: %s\n' % self.tag
		t += 'taglen: %s\n' % self.taglen
		t += 'tagdata: %s\n' % self.tagdata
		return t

class DateTime:
	def __init__(self):
		self.time_offset:int = None
		self.usec_offset:int = None
	
	@staticmethod
	def parse(reader:io.BytesIO):
		d = DateTime()
		d.time_offset = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		d.usec_offset = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		return d
		
	def to_bytes(self):
		t =  self.time_offset.to_bytes(4, byteorder='big', signed=False)
		t += self.usec_offset.to_bytes(4, byteorder='big', signed=False)
		return t

	@staticmethod
	def from_bytes(data:bytes):
		return DateTime.parse(io.BytesIO(data))
		

		
class Credential:
	def __init__(self):
		self.client = None
		self.server = None
		self.key = None
		self.time = None
		self.is_skey = None
		self.tktflags = None
		self.num_address = None
		self.addrs = []
		self.num_authdata = None
		self.authdata = []
		self.ticket = None
		self.second_ticket = None

	def to_hash(self):
		res = Ticket.load(self.ticket.to_asn1()).native
		tgs_encryption_type    = int(res['enc-part']['etype'])
		t = len(res['sname']['name-string'])
		if t == 1:
			tgs_name_string        = res['sname']['name-string'][0]
		else:
			tgs_name_string        = res['sname']['name-string'][1]
		tgs_realm              = res['realm']
		if tgs_encryption_type == EncryptionType.AES256_CTS_HMAC_SHA1_96.value:
			tgs_checksum           = res['enc-part']['cipher'][-12:]
			tgs_encrypted_data2    = res['enc-part']['cipher'][:-12]
			return '$krb5tgs$%s$%s$%s$%s$%s' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.hex(), tgs_encrypted_data2.hex() )
		else:
			tgs_checksum           = res['enc-part']['cipher'][:16]
			tgs_encrypted_data2    = res['enc-part']['cipher'][16:]
			return '$krb5tgs$%s$*%s$%s$spn*$%s$%s' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.hex(), tgs_encrypted_data2.hex() )

	def to_tgt(self):
		"""
		Returns the native format of an AS_REP message and the sessionkey in EncryptionKey native format
		"""
		enc_part = EncryptedData({'etype': 1, 'cipher': b''})
		
		tgt_rep = {}
		tgt_rep['pvno'] = krb5_pvno
		tgt_rep['msg-type'] = MESSAGE_TYPE.KRB_AS_REP.value
		tgt_rep['crealm'] = self.client.realm.to_string()
		tgt_rep['cname'] = self.client.to_asn1()[0]
		tgt_rep['ticket'] = Ticket.load(self.ticket.to_asn1()).native
		tgt_rep['enc-part'] = enc_part.native

		t = EncryptionKey(self.key.to_asn1()).native
		
		return tgt_rep, t

	def to_tgs(self):
		"""
		Returns the native format of an AS_REP message and the sessionkey in EncryptionKey native format
		"""
		enc_part = EncryptedData({'etype': 1, 'cipher': b''})
		
		tgt_rep = {}
		tgt_rep['pvno'] = krb5_pvno
		tgt_rep['msg-type'] = MESSAGE_TYPE.KRB_AS_REP.value
		tgt_rep['crealm'] = self.client.realm.to_string()
		tgt_rep['cname'] = self.client.to_asn1()[0]
		tgt_rep['ticket'] = Ticket.load(self.ticket.to_asn1()).native
		tgt_rep['enc-part'] = enc_part.native

		t = EncryptionKey(self.key.to_asn1()).native
		
		return tgt_rep, t
		
	def to_kirbi(self):
		filename = '%s@%s_%s' % (self.client.to_string() , self.server.to_string(), hashlib.sha1(self.ticket.to_asn1()).hexdigest()[:8])
		krbcredinfo = {}
		krbcredinfo['key'] = EncryptionKey(self.key.to_asn1())
		krbcredinfo['prealm'] = self.client.realm.to_string()
		krbcredinfo['pname'] = self.client.to_asn1()[0]
		krbcredinfo['flags'] = core.IntegerBitString(self.tktflags).cast(TicketFlags)
		if self.time.authtime != 0: #this parameter is not mandatory, and most of the time not present
			krbcredinfo['authtime'] = datetime.datetime.fromtimestamp(self.time.authtime, datetime.timezone.utc)
		if self.time.starttime != 0:
			krbcredinfo['starttime'] = datetime.datetime.fromtimestamp(self.time.starttime, datetime.timezone.utc)
		if self.time.endtime != 0:
			krbcredinfo['endtime'] = datetime.datetime.fromtimestamp(self.time.endtime, datetime.timezone.utc)
		if self.time.renew_till != 0: #this parameter is not mandatory, and sometimes it's not present
			krbcredinfo['renew-till'] = datetime.datetime.fromtimestamp(self.time.authtime, datetime.timezone.utc)
		krbcredinfo['srealm'] = self.server.realm.to_string()
		krbcredinfo['sname'] = self.server.to_asn1()[0]
		
		enc_krbcred = {}
		enc_krbcred['ticket-info'] = [KrbCredInfo(krbcredinfo)]
		
		krbcred = {}
		krbcred['pvno'] = krb5_pvno
		krbcred['msg-type'] = MESSAGE_TYPE.KRB_CRED.value
		krbcred['tickets'] = [Ticket.load(self.ticket.to_asn1())]
		krbcred['enc-part'] = EncryptedData({'etype': EncryptionType.NULL.value, 'cipher': EncKrbCredPart(enc_krbcred).dump()})

		kirbi = Kirbi(KRBCRED(krbcred))
		return kirbi, filename
	
	@staticmethod
	def from_kirbi(kirbi:Kirbi):
		krbcred = kirbi.kirbiobj.native
		c = Credential()
		enc_credinfo = EncKrbCredPart.load(krbcred['enc-part']['cipher']).native
		ticket_info = enc_credinfo['ticket-info'][0]
		
		c.client = CCACHEPrincipal.from_asn1(ticket_info['pname'], ticket_info['prealm'])
		#yaaaaay 4 additional weirdness!!!!
		#if sname name-string contains a realm as well htne impacket will crash miserably :(
		if len(ticket_info['sname']['name-string']) > 2 and ticket_info['sname']['name-string'][-1].upper() == ticket_info['srealm'].upper():
			logger.debug('SNAME contains the realm as well, trimming it')
			t = ticket_info['sname']
			t['name-string'] = t['name-string'][:-1]
			c.server = CCACHEPrincipal.from_asn1(t, ticket_info['srealm'])
		else:
			c.server = CCACHEPrincipal.from_asn1(ticket_info['sname'], ticket_info['srealm'])
		
		
		c.time = Times.from_asn1(ticket_info)
		c.key = Keyblock.from_asn1(ticket_info['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(ticket_info['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(Ticket(krbcred['tickets'][0]).dump()) #kirbi only stores one ticket per file
		c.second_ticket = CCACHEOctetString.empty()
		
		return c

	@staticmethod
	def from_asn1(ticket, data):
		###
		# data  = KrbCredInfo 
		###
		c = Credential()
		c.client = CCACHEPrincipal.from_asn1(data['pname'], data['prealm'])
		c.server = CCACHEPrincipal.from_asn1(data['sname'], data['srealm'])
		c.key = Keyblock.from_asn1(data['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(data['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(ticket['enc-part']['cipher'])
		c.second_ticket = CCACHEOctetString.empty()
		return c
	
	@staticmethod
	def parse(reader):
		c = Credential()
		c.client = CCACHEPrincipal.parse(reader)
		c.server = CCACHEPrincipal.parse(reader)
		c.key = Keyblock.parse(reader)
		c.time = Times.parse(reader)
		c.is_skey = int.from_bytes(reader.read(1), byteorder='big', signed=False)
		c.tktflags = int.from_bytes(reader.read(4), byteorder='little', signed=False)
		c.num_address = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		for _ in range(c.num_address):
			c.addrs.append(Address.parse(reader))
		c.num_authdata = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		for _ in range(c.num_authdata):
			c.authdata.append(Authdata.parse(reader))
		c.ticket = CCACHEOctetString.parse(reader)
		c.second_ticket = CCACHEOctetString.parse(reader)
		return c
	
	@staticmethod
	def summary_header():
		return ['client','server','starttime','endtime','renew-till']
		
	def summary(self):
		return [ 
			'%s@%s' % 	(self.client.to_string(separator='/'),self.client.realm.to_string()), 
			'%s@%s' % 	(self.server.to_string(separator='/'), self.server.realm.to_string()),
			datetime.datetime.fromtimestamp(self.time.starttime).isoformat() if self.time.starttime != 0 else 'N/A',
			datetime.datetime.fromtimestamp(self.time.endtime).isoformat() if self.time.endtime != 0 else 'N/A',
			datetime.datetime.fromtimestamp(self.time.renew_till).isoformat() if self.time.renew_till != 0 else 'N/A',
		
		]
		
	def to_bytes(self):
		t =  self.client.to_bytes()
		t += self.server.to_bytes()
		t += self.key.to_bytes()
		t += self.time.to_bytes()
		t += self.is_skey.to_bytes(1, byteorder='big', signed=False)
		t += self.tktflags.to_bytes(4, byteorder='little', signed=False)
		t += self.num_address.to_bytes(4, byteorder='big', signed=False)
		for addr in self.addrs:
			t += addr.to_bytes()
		t += self.num_authdata.to_bytes(4, byteorder='big', signed=False)
		for ad in self.authdata:
			t += ad.to_bytes()
		t += self.ticket.to_bytes()
		t += self.second_ticket.to_bytes()
		return t
		
class Keyblock:
	def __init__(self):
		self.keytype = None
		self.etype = None
		self.keylen = None
		self.keyvalue = None
	
	@staticmethod
	def from_asn1(data):
		k = Keyblock()
		k.keytype = data['keytype']
		k.etype = 0 # not sure
		k.keylen = len(data['keyvalue'])
		k.keyvalue = data['keyvalue']
		
		return k
		
	def to_asn1(self):
		t = {}
		t['keytype'] = self.keytype
		t['keyvalue'] = self.keyvalue
		
		return t
	
	@staticmethod
	def parse(reader):
		k = Keyblock()
		k.keytype = int.from_bytes(reader.read(2), byteorder='big', signed=True)
		k.etype = int.from_bytes(reader.read(2), byteorder='big', signed=True)
		k.keylen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.keyvalue = reader.read(k.keylen)
		return k
		
	def to_bytes(self):
		t = self.keytype.to_bytes(2, byteorder='big', signed=True)
		t += self.etype.to_bytes(2, byteorder='big', signed=True)
		t += self.keylen.to_bytes(2, byteorder='big', signed=False)
		t += self.keyvalue
		return t
		
		
class Times:
	def __init__(self):
		self.authtime = None
		self.starttime = None
		self.endtime = None
		self.renew_till = None
	
	@staticmethod
	def from_asn1(enc_as_rep_part):
		t = Times()
		t.authtime = dt_to_kerbtime(enc_as_rep_part['authtime']) \
			if 'authtime' in enc_as_rep_part and enc_as_rep_part['authtime'] else 0
		t.starttime = dt_to_kerbtime(enc_as_rep_part['starttime']) \
			if 'starttime' in enc_as_rep_part and enc_as_rep_part['starttime'] else 0
		t.endtime = dt_to_kerbtime(enc_as_rep_part['endtime']) \
			if 'endtime' in enc_as_rep_part and enc_as_rep_part['endtime'] else 0
		t.renew_till = dt_to_kerbtime(enc_as_rep_part['renew-till']) \
			if 'renew-till' in enc_as_rep_part and enc_as_rep_part['renew-till'] else 0
		return t
	
	@staticmethod
	def dummy_time(start= datetime.datetime.now(datetime.timezone.utc)):
		t = Times()
		t.authtime = dt_to_kerbtime(start)
		t.starttime = dt_to_kerbtime(start )
		t.endtime = dt_to_kerbtime(start + datetime.timedelta(days=1))
		t.renew_till = dt_to_kerbtime(start + datetime.timedelta(days=2))
		return t
	
	@staticmethod
	def parse(reader):
		t = Times()
		t.authtime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.starttime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.endtime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.renew_till = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		return t
		
	def to_bytes(self):
		t = self.authtime.to_bytes(4, byteorder='big', signed=False)
		t += self.starttime.to_bytes(4, byteorder='big', signed=False)
		t += self.endtime.to_bytes(4, byteorder='big', signed=False)
		t += self.renew_till.to_bytes(4, byteorder='big', signed=False)
		return t

	@staticmethod
	def from_bytes(data:bytes):
		return Times.parse(io.BytesIO(data))
		
class Address:
	def __init__(self):
		self.addrtype:int = None
		self.addrdata:CCACHEOctetString = None
	
	@staticmethod
	def parse(reader):
		a = Address()
		a.addrtype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		a.addrdata = CCACHEOctetString.parse(reader)
		return a
		
	def to_bytes(self):
		t = self.addrtype.to_bytes(2, byteorder='big', signed=False)
		t += self.addrdata.to_bytes()
		return t
	
	def from_bytes(data:bytes):
		return Address.parse(io.BytesIO(data))
		
class Authdata:
	def __init__(self):
		self.authtype:int = None
		self.authdata:CCACHEOctetString = None
	
	@staticmethod
	def parse(reader:io.BytesIO):
		a = Authdata()
		a.authtype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		a.authdata = CCACHEOctetString.parse(reader)
		return a
		
	def to_bytes(self):
		t = self.authtype.to_bytes(2, byteorder='big', signed=False)
		t += self.authdata.to_bytes()
		return t

	def from_bytes(data:bytes):
		return Authdata.parse(io.BytesIO(data))
		
class CCACHEPrincipal:
	def __init__(self):
		self.name_type:int = None
		self.num_components:int = None
		self.realm:CCACHEOctetString = None
		self.components:List[CCACHEOctetString] = []
	
	@staticmethod
	def from_asn1(principal, realm):
		p = CCACHEPrincipal()
		p.name_type = principal['name-type']
		p.num_components = len(principal['name-string'])
		p.realm = CCACHEOctetString.from_string(realm)
		for comp in principal['name-string']:
			p.components.append(CCACHEOctetString.from_asn1(comp))
			
		return p
	
	@staticmethod
	def empty():
		p = CCACHEPrincipal()
		p.name_type = 1
		p.num_components = 1
		p.realm = CCACHEOctetString.from_string('kerbi.corp')
		for _ in range(1):
			p.components.append(CCACHEOctetString.from_string('kerbi'))
			
		return p
		
	def to_string(self, separator = '-'):
		return separator.join([c.to_string() for c in self.components])
		
	def to_asn1(self):
		t = {'name-type': self.name_type, 'name-string': [name.to_string() for name in self.components]}
		return t, self.realm.to_string()

	def to_spn(self):
		return '/'.join([name.to_string() for name in self.components]) + '@' + self.realm.to_string()
	
	@staticmethod
	def parse(reader):
		p = CCACHEPrincipal()
		p.name_type = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		p.num_components = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		p.realm = CCACHEOctetString.parse(reader)
		for _ in range(p.num_components):
			p.components.append(CCACHEOctetString.parse(reader))
		return p
		
	def to_bytes(self):
		t = self.name_type.to_bytes(4, byteorder='big', signed=False)
		t += len(self.components).to_bytes(4, byteorder='big', signed=False)
		t += self.realm.to_bytes()
		for com in self.components:
			t += com.to_bytes()
		return t
	
	def __str__(self):
		t = self.realm.to_string() + '/'
		t += '/'.join([c.to_string() for c in self.components])
		return t
	
		
class CCACHEOctetString:
	def __init__(self):
		self.length:int = None
		self.data:bytes = None
	
	@staticmethod
	def empty():
		o = CCACHEOctetString()
		o.length = 0
		o.data = b''
		return o
		
	def to_asn1(self):
		return self.data
		
	def to_string(self):
		return self.data.decode()
	
	@staticmethod
	def from_string(data):
		o = CCACHEOctetString()
		o.data = data.encode()
		o.length = len(o.data)
		return o
	
	@staticmethod
	def from_asn1(data):
		o = CCACHEOctetString()
		o.length = len(data)
		if isinstance(data,str):
			o.data = data.encode()
		else:
			o.data = data
		return o
	
	@staticmethod
	def parse(reader):
		o = CCACHEOctetString()
		o.length = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		o.data = reader.read(o.length)
		return o
		
	def to_bytes(self):
		if isinstance(self.data,str):
			self.data = self.data.encode()
			self.length = len(self.data)
		t = len(self.data).to_bytes(4, byteorder='big', signed=False)
		t += self.data
		return t

	def __eq__(self, __o: object) -> bool:
		if isinstance(__o, CCACHEOctetString):
			return self.to_bytes() == __o.to_bytes()
		return False
		
		
class CCACHE:
	"""
	As the header is rarely used -mostly static- you'd need to init this object with empty = True to get an object without header already present
	"""
	def __init__(self, empty = False):
		self.file_format_version = None #0x0504
		self.headers = []
		self.primary_principal = None
		self.credentials:List[Credential] = []
		
		if empty == False:
			self.__setup()
		
	def __setup(self):
		self.file_format_version = 0x0504
		header = Header()
		header.tag = 1
		header.taglen = 8
		header.tagdata = b'\x00\x00\x00\x00\x00\x00\x00\x00'
		self.headers.append(header)
		
		self.primary_principal = CCACHEPrincipal.empty()
		
	def __str__(self):
		t = '== CCACHE ==\n'
		t+= 'file_format_version : %s\n' % self.file_format_version
		for header in self.headers:
			t+= '%s\n' % header
		t+= 'primary_principal : %s\n' % self.primary_principal
		return t
		
	def add_tgt(self, as_rep, enc_as_rep_part, override_pp = True): #from AS_REP
		"""
		Creates credential object from the TGT and adds to the ccache file
		The TGT is basically the native representation of the asn1 encoded AS_REP data that the AD sends upon a succsessful TGT request.
		
		This function doesn't do decryption of the encrypted part of the as_rep object, it is expected that the decrypted XXX is supplied in enc_as_rep_part
		
		override_pp: bool to determine if client principal should be used as the primary principal for the ccache file
		"""
		c = Credential()
		c.client = CCACHEPrincipal.from_asn1(as_rep['cname'], as_rep['crealm'])
		if override_pp == True:
			self.primary_principal = c.client
		c.server = CCACHEPrincipal.from_asn1(enc_as_rep_part['sname'], enc_as_rep_part['srealm'])
		c.time = Times.from_asn1(enc_as_rep_part)
		c.key = Keyblock.from_asn1(enc_as_rep_part['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(enc_as_rep_part['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(Ticket(as_rep['ticket']).dump())
		c.second_ticket = CCACHEOctetString.empty()
		
		self.credentials.append(c)
		
	def add_tgs(self, tgs_rep, enc_tgs_rep_part, override_pp = False): #from AS_REP
		"""
		Creates credential object from the TGS and adds to the ccache file
		The TGS is the native representation of the asn1 encoded TGS_REP data when the user requests a tgs to a specific service principal with a valid TGT
		
		This function doesn't do decryption of the encrypted part of the tgs_rep object, it is expected that the decrypted XXX is supplied in enc_as_rep_part
		
		override_pp: bool to determine if client principal should be used as the primary principal for the ccache file
		"""
		c = Credential()
		c.client = CCACHEPrincipal.from_asn1(tgs_rep['cname'], tgs_rep['crealm'])
		if override_pp == True:
			self.primary_principal = c.client
		c.server = CCACHEPrincipal.from_asn1(enc_tgs_rep_part['sname'], enc_tgs_rep_part['srealm'])
		c.time = Times.from_asn1(enc_tgs_rep_part)
		c.key = Keyblock.from_asn1(enc_tgs_rep_part['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(enc_tgs_rep_part['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(Ticket(tgs_rep['ticket']).dump())
		c.second_ticket = CCACHEOctetString.empty()
		
		self.credentials.append(c)
	
		
	def add_kirbi(self, kirbi:Kirbi, override_pp = True):
		c = Credential.from_kirbi(kirbi)
		if override_pp == True:
			self.primary_principal = c.client		
		self.credentials.append(c)

	def get_all_tgt_kirbis(self):
		"""
		Returns a list of AS_REP tickets in kirbi format (Kirbi). 
		To determine which ticket are AP_REP we check for the server principal to be the kerberos service
		"""
		tgts = []
		for cred in self.credentials:
			if cred.server.to_string(separator = '/').lower().find('krbtgt') != -1:
				tgts.append(cred.to_kirbi()[0])

		return tgts

	def get_all_tgt(self):
		"""
		Returns a list of AS_REP tickets in native format (dict). 
		To determine which ticket are AP_REP we check for the server principal to be the kerberos service
		"""
		tgts = []
		for cred in self.credentials:
			if cred.server.to_string(separator = '/').lower().find('krbtgt') != -1:
				tgts.append(cred.to_tgt())

		return tgts
	
	def get_tgs(self, spn:KerberosSPN, strict:bool=False):
		tgss = self.get_all_tgs()
		for tgs, keystruct in tgss:
			ticket_for = ('/'.join(tgs['ticket']['sname']['name-string'])) + '@' + tgs['ticket']['realm']
			if ticket_for.upper() == str(spn).upper():
				logger.debug('Found TGS for SPN %s' % ticket_for)
				return tgs, keystruct, None
		if strict is True:
			return None, None, Exception('No TGS found for SPN %s' % spn)
		
		# I hope you know what you are doing at this point...
		# Couldn't find the correct TGS for the SPN, returning the first one
		# the only valid reason this can happen is mismatching service tag in the SPN
		# this is a hack...
		if len(tgss) == 0:
			return None, None, Exception('No TGS found in CCACHE file')
		return tgss[0][0], tgss[0][1], None
	
	def get_tgt(self, username, domain = None, strict:bool=False):
		tgts = [x for x in self.get_all_tgt()]
		if len(tgts) == 0:
			return None, None, Exception('No TGT found in CCACHE file')
		
		if strict is False:
			if username is None:
				#no username was supplied, returning first TGT and hope for the best
				logger.debug('Missing username, returning first availabla TGT!')
				return tgts[0][0], tgts[0][1], None
			if domain is None:
				# no domain was supplied, trying to find a TGT for the user in any domain
				for tgt, keystruct in tgts:
					if tgt['cname']['name-string'].find(str(username)) != -1:
						logger.debug('Found TGT for user %s' % username)
						return tgt, keystruct, None
					
				# no TGT found for the user in any domain
				# returning first TGT and hope for the best
				logger.debug('Missing domain, user not found, returning first availabla TGT!')
				return tgts[0][0], tgts[0][1], None

			# at this point it seems that both username and domain is supplied
			# proceeding as if strict check was true

		for tgt, keystruct in tgts:
			our_user = str(username) + '@' + str(domain)
			ticket_for = '/'.join(tgt['cname']['name-string']) + '@' + tgt['crealm']
			if ticket_for.upper() == our_user.upper():
				logger.debug('Found TGT for user %s' % our_user)
				return tgt, keystruct, None
		
		if strict is False:
			# no TGT found for the user in any domain
			# returning first TGT and hope for the best
			logger.debug('domain+user combo not found, returning first availabla TGT!')
			return tgts[0][0], tgts[0][1], None

		return None, None, Exception('No TGT found for user %s' % our_user)

	def get_all_tgs(self):
		tgss = []
		for cred in self.credentials:
			if cred.server.to_string(separator = '/').lower().find('krbtgt') == -1:
				tgss.append(cred.to_tgs())

		return tgss

	def get_hashes(self):
		"""
		Returns a list of hashes in hashcat-firendly format for tickets with encryption type 23 (which is RC4)
		all_hashes: overrides the encryption type filtering and returns hash for all tickets

		"""
		hashes = []
		for cred in self.credentials:
			hashes.append(cred.to_hash())

		return hashes
		
	@staticmethod
	def parse(reader:io.BytesIO):
		c = CCACHE(True)
		c.file_format_version = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		
		hdr_size = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		c.headers = Header.parse(reader.read(hdr_size))
		#c.headerlen = 
		#for i in range(c.headerlen):
		#	c.headers.append(Header.parse(reader))
		
		
		c.primary_principal = CCACHEPrincipal.parse(reader)
		pos = reader.tell()
		reader.seek(-1,2)
		eof = reader.tell()
		reader.seek(pos,0)
		while reader.tell() < eof:
			cred = Credential.parse(reader)
			if not (len(cred.server.components) > 0 and cred.server.components[0].to_string() == 'krb5_ccache_conf_data'
			and cred.server.realm.to_string() == 'X-CACHECONF:'):
				c.credentials.append(cred)
		
		return c
		
	def to_bytes(self):
		t = self.file_format_version.to_bytes(2, byteorder='big', signed=False)
		
		t_hdr = b''
		for header in self.headers:
			t_hdr += header.to_bytes()
		
		t += len(t_hdr).to_bytes(2, byteorder='big', signed=False)
		t += t_hdr
		
		t += self.primary_principal.to_bytes()
		for cred in self.credentials:
			t += cred.to_bytes()
		return t

	def list_targets(self):
		for cred in self.credentials:
			target = cred.server
			yield target.to_spn()

	@staticmethod
	def from_kirbi(kirbidata:Kirbi):
		if isinstance(kirbidata, Kirbi) is False:
			kirbi = Kirbi.from_bytes(kirbidata)
		else:
			kirbi = kirbidata
		cc = CCACHE()
		cc.add_kirbi(kirbi)
		return cc
	
	@staticmethod
	def from_kirbifile(kirbi_filename:str):
		kf_abs = os.path.abspath(kirbi_filename)
		kirbidata = None
		with open(kf_abs, 'rb') as f:
			kirbidata = f.read()
		try:
			ccache = CCACHE.from_kirbi(kirbidata)
		except:
			#maybe the kirbi file is actually base64 encoded from rubeus?
			kirbi = Kirbi.from_b64(kirbidata)
			ccache = CCACHE.from_kirbi(kirbi)
		
		return ccache
	
	@staticmethod
	def from_kirbidir(directory_path):
		"""
		Iterates trough all .kirbi files in a given directory and converts all of them into one CCACHE object
		"""
		cc = CCACHE()
		dir_path = os.path.join(os.path.abspath(directory_path), '*.kirbi')
		for filename in glob.glob(dir_path):
			kirbi = Kirbi.from_file(filename)
			cc.add_kirbi(kirbi)
		
		return cc
		
	def to_kirbidir(self, directory_path:str):
		"""
		Converts all credential object in the CCACHE object to the kirbi file format used by mimikatz.
		The kirbi file format supports one credential per file, so prepare for a lot of files being generated.
		
		directory_path: str the directory to write the kirbi files to
		"""
		kf_abs = os.path.abspath(directory_path)
		for cred in self.credentials:
			kirbi, filename = cred.to_kirbi()
			filename = '%s.kirbi' % filename.replace('..','!')
			filepath = os.path.join(kf_abs, filename)
			kirbi.to_file(filepath)
	
	@staticmethod
	def from_file(filename):
		"""
		Parses the ccache file and returns a CCACHE object
		"""
		with open(filename, 'rb') as f:
			return CCACHE.parse(f)
			
	def to_file(self, filename):
		"""
		Writes the contents of the CCACHE object to a file
		"""
		with open(filename, 'wb') as f:
			f.write(self.to_bytes())
		
	@staticmethod
	def from_bytes(data):
		return CCACHE.parse(io.BytesIO(data))

	@staticmethod
	def from_hex(hexdata):
		return CCACHE.from_bytes(bytes.fromhex(hexdata))
	
	def to_hex(self):
		return self.to_bytes().hex()
	
	def to_b64(self):
		return base64.b64encode(self.to_bytes()).decode('ascii')

	@staticmethod
	def from_b64(b64data):
		return CCACHE.from_bytes(base64.b64decode(b64data))
